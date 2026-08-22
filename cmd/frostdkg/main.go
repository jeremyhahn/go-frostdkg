// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

func main() {
	// Bring up the secure-memory subsystem before anything can allocate a
	// secret. Init installs an interrupt handler that purges every enclave on
	// a termination signal, which is the only thing standing between a
	// Ctrl-C and key material left in a core dump.
	secmem.Init()

	// Purge, not defer-and-hope: os.Exit below skips deferred calls, so the
	// error path purges explicitly before exiting.
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		secmem.Purge()
		os.Exit(1)
	}
	secmem.Purge()
}
