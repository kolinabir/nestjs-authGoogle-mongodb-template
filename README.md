# NestJS Google Authentication Template

This project provides a ready-to-use NestJS template with Google authentication and MongoDB integration.

## Setup
1. Clone the repository:
```
git clone https://github.com/your-username/nestjs-authGoogle-mongodb-template.git
```
2. Install dependencies:
```
cd nestjs-authGoogle-mongodb-template
npm install
```
3. Set up environment variables:
   - Create a `.env` file in the project root with the following:
     ```
     mongoDBUrl=mongodb://localhost:27017/nest-auth
     jwt_secret=secret124s
     GOOGLE_CLIENT_ID=<your_google_client_id>
     GOOGLE_CLIENT_SECRET=<your_google_client_secret>
     GOOGLE_CALLBACK_URL=http://localhost:4000/auth/google/redirect
     ```
   - Replace the placeholders with your actual Google OAuth credentials.

4. Start the development server:
```
npm run start:dev
```

## Google Authentication APIs

### Google Login
`@Get('google-login')`: Triggers the Google authentication flow, redirecting the user to the Google login page.

### Google Redirect
`@Get('google/redirect')`: Handles the redirect after successful Google authentication, redirecting the user to the frontend.

### Get Current User
`@Get('me')`: Returns the currently authenticated user, or `{ authenticated: false }`.

### Logout
`@Get('logout')`: Logs out the user by destroying the session and clearing the session cookie.

### Protected Route
`@Get('protected')`: A protected route accessible only to authenticated users.

## Google OAuth Setup
1. Go to the Google Cloud Console and create/select a project.
2. Enable the Google+ API.
3. In "Credentials", create an "OAuth client ID".
4. Select "Web application" type.
5. Add the `GOOGLE_CALLBACK_URL` as an authorized redirect URI.
6. Save the client ID and secret, and update the `.env` file.

The callback URL is the endpoint that Google will redirect to after successful authentication.
