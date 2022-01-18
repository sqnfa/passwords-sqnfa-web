# Passwords are sqnfa and web
> Implementation of best practice client-side password handling.

Passwords are still essential for most applications. This also includes web applications. This library implements the recommendations that apply to client-side password handling from the National Institute of Standards and Technology (NIST) and the Open Web Application Security Project (OWASP). The purpose of this library is to provide an easy pluggable client-side password preprocessor. It is not a substitute for the proper handling of passwords in the backend and should only be considered an extra layer.

# Usage
Include the minified build and access the main password handler directly.
```javascript
const handler = new PasswordsSqnfaWeb.PasswordsSqnfaWeb()
    .useLengthHandler()
    .useEmailBlackListHandler({email, slidingWindow, minTokenLength})
    .useBlackListHandler({caseInsensitiveWords, regExps}, true)
    .useHaveibeenpwnedHandler({pwnedPasswordsUrl, httpClient}, true)
    .useBcryptHandler({salt})

const result = passwordHandler.handle(password)

if(result.isSuccess) {
    console.log("Preprocessed password is: ", result.getPassword())
} else {
    console.log("One or more rules broken: ", result.getFailures())
}
```
The order of chaining is important. In the above example, the length policy is handled first, then the e-mail black list policy.
This is followed by the black list policy. The second parameter `true` in the `useBlackListHandler` method tells the PasswordsSqnfaWeb handler
to stop the execution, if this or any of previous handlers contained one or more failed results. If and only if the first three handlers are successful,
then the password will be validated towards the haveibeenpwned API. Finally, if the password has not been part of previous breach corpses, then the 
password is hashed by the bcrypt algorithm.

See a complete example in vanilla javascript in `examples/vanilla.html`.

# API
ToDo

# Installation
`npm install passwords-sqnfa-web`

# Futher examples
ToDo

# Background
The acronym sqnfa is short hand of "sine qua non for applications". 
Sine qua non is Latin and literally translates to "without which, not".
All projects within the sqnfa organization are meant to be reusable and easy pluggable in all types of modern applications.

# License
Apache 2.0
