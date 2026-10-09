// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-frostdkg.
//
// go-frostdkg is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>
//
// 2. Commercial License
//    Contact: licensing@automatethethings.com
//
// SPDX-License-Identifier: AGPL-3.0 OR Commercial

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// resolveParticipantListen runs the root command's config/env setup and
// returns the participant's listen address as the CLI would resolve it.
// An empty argument means that layer is not set.
func resolveParticipantListen(t *testing.T, flagValue, envValue, fileValue string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := "protocol: libp2p\n"
	if fileValue != "" {
		content += "participant:\n  listen: \"" + fileValue + "\"\n"
	}
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	oldCfg := cfgFile
	cfgFile = configPath
	listenFlag := participantCmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag)
	// Other tests call viper.Reset(), which drops the init()-time flag binding
	// and the env settings; start from a clean viper with the flag bound, and
	// leave one behind, so no case depends on what ran before it.
	freshViper := func() {
		viper.Reset()
		require.NoError(t, viper.BindPFlag("participant.listen", listenFlag))
	}
	freshViper()
	t.Cleanup(func() {
		cfgFile = oldCfg
		_ = listenFlag.Value.Set("")
		listenFlag.Changed = false
		freshViper()
	})

	if envValue != "" {
		t.Setenv("FROSTDKG_PARTICIPANT_LISTEN", envValue)
	}
	if flagValue != "" {
		require.NoError(t, participantCmd.Flags().Set("listen", flagValue))
	}

	rootCmd.PersistentPreRun(rootCmd, nil)
	return viper.GetString("participant.listen")
}

func TestParticipantListenDefaultsToUnset(t *testing.T) {
	// Unset means the library's defaults layer applies (an ephemeral port).
	require.Equal(t, "", resolveParticipantListen(t, "", "", ""))
}

func TestParticipantListenFromTheConfigFile(t *testing.T) {
	require.Equal(t, "127.0.0.1:19001", resolveParticipantListen(t, "", "", "127.0.0.1:19001"))
}

func TestParticipantListenFromTheEnvironment(t *testing.T) {
	require.Equal(t, "127.0.0.1:19002", resolveParticipantListen(t, "", "127.0.0.1:19002", ""))
}

func TestParticipantListenFromTheFlag(t *testing.T) {
	require.Equal(t, "127.0.0.1:19003", resolveParticipantListen(t, "127.0.0.1:19003", "", ""))
}

func TestParticipantListenPrecedence(t *testing.T) {
	t.Run("env beats the config file", func(t *testing.T) {
		require.Equal(t, "127.0.0.1:19011", resolveParticipantListen(t, "", "127.0.0.1:19011", "127.0.0.1:19010"))
	})
	t.Run("flag beats env and the config file", func(t *testing.T) {
		require.Equal(t, "127.0.0.1:19012", resolveParticipantListen(t, "127.0.0.1:19012", "127.0.0.1:19011", "127.0.0.1:19010"))
	})
}
