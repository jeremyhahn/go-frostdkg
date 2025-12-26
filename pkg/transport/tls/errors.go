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

package tls

import "errors"

var (
	// ErrCertificateNotFound is returned when the certificate file cannot be found
	ErrCertificateNotFound = errors.New("certificate file not found")

	// ErrKeyNotFound is returned when the private key file cannot be found
	ErrKeyNotFound = errors.New("private key file not found")

	// ErrCANotFound is returned when the CA certificate file cannot be found
	ErrCANotFound = errors.New("CA certificate file not found")

	// ErrInvalidCertificate is returned when the certificate is invalid or cannot be parsed
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrInvalidKey is returned when the private key is invalid or cannot be parsed
	ErrInvalidKey = errors.New("invalid private key")

	// ErrCertKeyMismatch is returned when the certificate and key do not match
	ErrCertKeyMismatch = errors.New("certificate and key do not match")

	// ErrInvalidCAPool is returned when the CA pool cannot be created
	ErrInvalidCAPool = errors.New("invalid CA certificate pool")

	// ErrEmptyCertificate is returned when empty certificate data is provided
	ErrEmptyCertificate = errors.New("empty certificate data")

	// ErrEmptyKey is returned when empty key data is provided
	ErrEmptyKey = errors.New("empty key data")
)
