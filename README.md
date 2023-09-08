## Authorization

In Form login there is a session for each user who is logged in. That is, our application remembers the logged in user for few moments.
But in the case of JWT auth or Rest api, our application does not remember anyone. For each request user needs to send his credentials or a valid token.
Then our application validates the token and authenticate that user for only that request if the token valid.
