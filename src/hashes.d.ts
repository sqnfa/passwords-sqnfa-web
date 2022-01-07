/**
 * Copyright (c) 2012-2017, Tomas Aparicio
 * Copyright (c) 1999-2012, Paul Johnston, Angel Marin, Jeremy Lin
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
declare module 'jshashes' {
  class HashesClass {
    /**
     * Hexadecimal hash encoding from string.
     */
    hex(input: string): string;

    /**
     * Base64 hash encoding from string.
     */
    b64(input: string): string;

    /**
     * Custom hash algorithm values encoding.
     */
    any(input: string, encoding: string): string;

    /**
     * Hexadecimal hash with HMAC salt key.
     */
    hex_hmac(key: string, input: string): string;

    /**
     * Custom hash values encoding with HMAC salt key support.
     */
    b64_hmac(key: string, input: string): string;

    /**
     * Custom hash values encoding with HMAC salt key support.
     */
    any_hmac(key: string, input: string, encoding: string): string;

    /**
     * Simple self-test to see if working.
     */
    vm_test(): this;

    /**
     * Enable/disable uppercase hexadecimal returned string.
     */
    setUpperCase(isEnabled: boolean): this;

    /**
     * Defines a custom base64 pad string. Default is '=' according with the RFC standard.
     */
    setPad(pad: string): this;

    /**
     * Enable/disable UTF-8 character encoding.
     */
    setUTF8(isEnabled: boolean): this;
  }

  namespace Hashes {
    export class MD5 extends HashesClass {}
    export class SHA1 extends HashesClass {}
    export class SHA256 extends HashesClass {}
    export class SHA512 extends HashesClass {}
    export class RMD160 extends HashesClass {}
  }

  export = Hashes;
}
