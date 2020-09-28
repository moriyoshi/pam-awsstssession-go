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

import "fmt"

func replacePlaceholders(template string, placeholders map[string]string) (string, error) {
	s := -1
	ss := 0
	result := make([]byte, 0, len(template))
	for i, c := range template {
		if s >= 0 {
			if c == '}' {
				n := template[s+1 : i]
				v, ok := placeholders[n]
				if !ok {
					return "", fmt.Errorf("unknown placeholder: %s", n)
				}
				result = append(result, v...)
				ss = i + 1
				s = -1
			}
		} else {
			if c == '{' {
				result = append(result, template[ss:i]...)
				s = i
			}
		}
	}
	if s != -1 {
		return "", fmt.Errorf("unclosed placeholder: %s", template[s:])
	}
	if ss < len(template) {
		result = append(result, template[ss:]...)
	}
	return string(result), nil
}
