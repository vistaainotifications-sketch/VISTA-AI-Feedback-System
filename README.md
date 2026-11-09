# VISTA AI Feedback System

## Deploy as a new Render service
1. Create a new GitHub repository (for example `VISTA-AI-Feedback`). Upload all files in this folder.
2. In Render, create a NEW PostgreSQL database for this feedback project.
3. Create a new Web Service connected to that repository.
4. Build command: `npm install` | Start command: `npm start`.
5. Add environment variables: `DATABASE_URL` = database Internal URL; `ADMIN_EMAIL` = your admin email; `ADMIN_PASSWORD_HASH` = bcrypt hash of a strong password; `DATABASE_SSL` = `true`.
6. Generate hash locally after installing dependencies: `node -e "import('bcryptjs').then(async b=>console.log(await b.hash(process.argv[1],12)))" 'YOUR_PASSWORD'`.

The public form runs at the service root. `/api/health` checks service/database configuration. Feedback is stored in PostgreSQL. Admin login/list/approve/reject/delete APIs are included, but a visual admin dashboard is not included in this first version. Do not reuse Command Center credentials or database unless intentionally sharing infrastructure. Never share passwords or connection strings in chat.
