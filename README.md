# Passwords are sqnfa and web

> Implementation of best practice client-side password handling.

Passwords are still essential for most applications. This also includes web applications. This library implements the recommendations that apply to client-side password handling from the National Institute of Standards and Technology (NIST) and the Open Web Application Security Project (OWASP). The purpose of this library is to provide an easy pluggable client-side password preprocessor. It is not a substitute for the proper handling of passwords in the backend and should only be considered an extra layer.

## Usage

Include the minified build and access the main password handler directly.

```javascript
const passwordHandler = new PasswordsSqnfaWeb.PasswordsSqnfaWeb()
    .useLengthHandler()
    .useEmailBlackListHandler({email, slidingWindow, minTokenLength})
    .useBlackListHandler({caseInsensitiveWords, regExps}, true)
    .useHaveibeenpwnedHandler({pwnedPasswordsUrl, httpClient}, true)
    .useBcryptHandler({salt})

const result = passwordHandler.handle(password)

if(result.isSuccess) {
    console.log("Preprocessed password is: ", result.getPassword())
} else {
    console.log("One or more policies are broken: ", result.getFailures())
}
```

The order of chaining is important. In the above example, the length policy is handled first, then the e-mail black list policy.
This is followed by the black list policy. The second parameter `true` in the `useBlackListHandler` method tells the PasswordsSqnfaWeb handler
to stop the execution, if this or any of previous handlers contained one or more failed results. If and only if the first three handlers are successful,
then the password will be validated towards the haveibeenpwned API. Finally, if the password has not been part of previous breach corpses, then the
password is hashed by the bcrypt algorithm.

See a complete example in vanilla javascript in `examples/vanilla.html`.

## Installation

`npm install passwords-sqnfa-web`

## API

Below is a rationale why each of the handlers are included in this library. Each contain a reference to NIST or OWASP guidelines. They are written in the order of execution preferences such that the user experience (UX) can be maximized with respect to the running time. This can be acheived by setting the `stopOnFailure` to `true` before any time consuming handlers are called.

Some handlers processes the actual password (`Sha512Handler` and `BcryptHandler`). The value of the original password will not be known to handlers executed after this. This means that each handler "sees" the password as the result of the previous handler.

### useLengthHandler(config?: LengthHandlerConfiguration, stopOnFailure = false)

NIST 800-63B: Password length has been found to be a primary factor in characterizing password strength. [...] Extremely long passwords (perhaps megabytes in length) could conceivably require excessive processing time to hash, so it is reasonable to have some limit. [...] Accordingly, at LOA2, SP 800-63-2 permitted the use of randomly generated PINs with 6 or more digits while requiring user-chosen memorized secrets to be a minimum of 8 characters long.

**PARAMETERS**

- `config?`: LengthHandlerConfiguration - See below
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

**LengthHandlerConfiguration**

- `minLength`: number - The minimum number of characters in the password. Defaults to 8.
- `maxByteSize`: number - The maximum number of bytes the password is represented in UTF8 code units. Defaults to 2097152 (2 MiB).

### useEmailBlackListHandler(config: EmailBlackListConfiguration, stopOnFailure = false)

NIST 800-63B: Password complexity: Users’ password choices are very predictable, so attackers are likely to guess passwords that have been successful in the past. For this reason, it is recommended that passwords chosen by users be compared against a “black list” of unacceptable passwords. This list should include specific words (such as the name of the service itself) that users are likely to choose.

This handler black lists passwords containing parts of the user's e-mail address. The e-mail is tokenized and each token is added to the black list.

**PARAMETERS**

- `config`: EmailBlackListConfiguration - See below
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

**EmailBlackListConfiguration**

- `email`: string - The information contained within the e-mail will be added to the black list.
- `slidingWindow`: number - The size of the sliding window used when tokenizing the email (The value 0 disables sliding window).
- `minTokenLength`: number - A safe-gaurd to ensure that shorter tokens are not added, i.e. ensure that the handler is not too restrictive.

### useBlackListHandler(config: BlackListConfiguration, stopOnFailure = false)

NIST 800-63B: Password complexity: Users’ password choices are very predictable, so attackers are likely to guess passwords that have been successful in the past. For this reason, it is recommended that passwords chosen by users be compared against a “black list” of unacceptable passwords. This list should include dictionary words, and specific words (such as the name of the service itself) that users are likely to choose.

This handler black lists passwords containing parts of black listed words or passwords that matches defined regular expressions. One or more e-mail addresses can be added. The e-mail is tokenized and each token is added to the black list.

**PARAMETERS**

- `config`: BlackListConfiguration - See below
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

**BlackListConfiguration**

- `caseInsensitiveWords`: string[] - A list of black listed words. Both the password and every words are compared with toLocaleUpperCase.
- `regExps`: RegExp[] - A list of black listed regular expressions. Each expression is compared with the original password.

### useHaveibeenpwnedHandler(config: HaveibeenpwnedConfiguration, stopOnFailure = false)

NIST 800-63B: Password complexity: Users’ password choices are very predictable, so attackers are likely to guess passwords that have been successful in the past. For this reason, it is recommended that passwords chosen by users be compared against a “black list” of unacceptable passwords. This list should include passwords from previous breach corpuses. The web service haveibeenpwned.com is a free resource for anyone to quickly assess if they may have been put at risk due to an online account of theirs having been compromised or "pwned" in a data breach.

**PARAMETERS**

- `config`: HaveibeenpwnedConfiguration - See below
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

**HaveibeenpwnedConfiguration**

- `pwnedPasswordsUrl`: string - The enpoint to he pwned passwords range search that ensures k-anonymity while looking for breaches. Defaults to <https://api.pwnedpasswords.com/range/>
- `httpClient`: HaveibeenpwnedHttpClient - Bring your own http client that does the actual call to the API.

**HaveibeenpwnedHttpClient.get(url: string): Promise<string[]>**
The only method that the interface `HaveibeenpwnedHttpClient` requries to be implemented is `get`.

- Parameter `url`: string - the full URL to invoke a `GET` request.
- Return `Promise<string[]>` - A promise that contains a list of SHA1 hash suffixes.

### useSha512Handler(stopOnFailure = false)

NIST 800-107: Some applications may require a value that is shorter than the (full-length) message digest provided by an approved hash function as specified in FIPS 180-4. In such cases, it may be appropriate to use a subset of the bits produced by the hash function as the (shortened) message digest.
  
This handler calculates the SHA512/432 of the password and encode the result in base64. This makes the encoded digest 72 bytes making it fit perfectly into bcrypt.

**PARAMETERS**

- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

### useBcryptHandler(config: BcryptConfiguration, stopOnFailure = false)

Bcrypt can be used as a means for server releif. It is a feature that allows the server to delegate the most expensive part of hashing to the client. The server, however, still need to treat the received value as a password and it has to undergo at least a preimage-resistant function. Another benefit is that the users original password is never sent to the server. Should the server leak an bcrypt hashed password, then an adversary would not be able to recover the actual password.

Note: Bcrypt limits the password length to be 72 encoded in utf-8. Should the users password be longer than this, then the password will automatically be hashed with SHA512/432 and encoded in base64 before being hashed by bcrypt.

**PARAMETERS**

- `config`: BcryptConfiguration - See below
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

**BcryptConfiguration**

- `salt`: string - A user specific salt on the format `$2a$[cost]$[22 character salt]`. This should come from the backend based on the user's identifier (or similar). OWASP recommends that the cost is 10. If cost is less than 10, then it should be prefixed with 0, e.g. 08.

### use(handler: Handler, stopOnFailure = false)

Bring your own handler. Any instance that implements the Handler interface can be added.

Please bear in mind that high password complexity requriements does not always yield highly secure passwords chosen by the user.

**PARAMETERS**

- `handler`: Handler - An asyncronous implementaion of the handler interface.
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

### useSync(handler: HandlerSync, stopOnFailure = false)

Bring your own handler. Any instance that implements the HandlerSync interface can be added.

Please bear in mind that high password complexity requriements does not always yield highly secure passwords chosen by the user.

**PARAMETERS**

- `handler`: HandlerSync - A syncronous implementaion of the handler interface.
- `stopOnFailure`: boolean - If true, the execution will stop, if any failures has happened to this point.

**RETURNS**

The current instance of `PasswordsSqnfaWeb` which allows chaining of the use* methods.

### statistics

A key-value property that contains the name of handlers that has been run as key and their total running time statistics in milliseconds as value.

## Futher examples

A web page using the Angular framework is under development. The goal of this web page is to collect statistics for the various handlers.

## Background

The acronym sqnfa is short hand of "sine qua non for applications".
Sine qua non is Latin and literally translates to "without which, not".
All projects within the sqnfa organization are meant to be reusable and easy pluggable in all types of modern applications.

## License

Apache 2.0
