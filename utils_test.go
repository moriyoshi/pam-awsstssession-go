// Copyright (c) 2020 Moriyoshi Koizumi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplacePlaceholders(t *testing.T) {
	cases := []struct {
		expected     string
		err          error
		template     string
		placeholders map[string]string
	}{
		{
			expected:     "abc",
			err:          nil,
			template:     "abc",
			placeholders: map[string]string{},
		},
		{
			expected:     "Abc",
			err:          nil,
			template:     "{a}bc",
			placeholders: map[string]string{"a": "A"},
		},
		{
			expected:     "aBc",
			err:          nil,
			template:     "a{b}c",
			placeholders: map[string]string{"b": "B"},
		},
		{
			expected:     "abC",
			err:          nil,
			template:     "ab{c}",
			placeholders: map[string]string{"c": "C"},
		},
	}
	for _, case_ := range cases {
		actual, err := replacePlaceholders(case_.template, case_.placeholders)
		if case_.err != nil {
			assert.Error(t, case_.err, err)
		} else {
			assert.Equal(t, case_.expected, actual)
		}
	}
}
