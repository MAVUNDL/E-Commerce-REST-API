# E-Commerce API

A RESTful e-commerce API built with Node.js, Express.js, and PostgreSQL, hosted on AWS (database) and Render (API server). This API is designed for a small e-commerce project focusing on Dell and Lenovo laptop products. It is open-source to provide free access to product data and authentication features.

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Setup & Installation](#setup--installation)
- [API Endpoints](#api-endpoints)
- [Error Handling](#error-handling)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features
- User authentication (SignUp/SignIn with JWT)
- Email verification & password reset flow
- Dell and Lenovo product catalog management
- Refresh token mechanism
- OTP verification

## Technologies Used
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL (Hosted on AWS RDS)
- **Authentication**: JWT, Bcrypt
- **Email Service**: Nodemailer
- **Hosting**: Render (API), AWS (Database)

## Setup & Installation

### Prerequisites
- Node.js v16+
- PostgreSQL
- AWS account (for database hosting)
- Render account (for API deployment)

### 1. Clone Repository
```bash
git clone https://github.com/MAVUNDL/E-Commerce-REST-API.git
cd Easy-Oder back-end
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Variables
Create a `.env` file with:
```env
DATABASE_URL=postgres://user:password@aws-hostname:port/dbname
JWT_SECRET=your_jwt_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
SMTP_HOST=your_smtp_host
SMTP_PORT=465
SMTP_USER=your_email@domain.com
SMTP_PASS=your_email_password
```

### 4. Database Setup
- Run migrations using your preferred ORM (e.g., Sequelize)
- Ensure AWS RDS instance is configured with proper security groups

### 5. Start Server
```bash
node server.js
```
Runs on `http://localhost:5000` by default.

## API Endpoints

### Authentication
| Method | Endpoint              | Description                     |
|--------|----------------------|---------------------------------|
| POST   | `/signUp`           | Register new user              |
| POST   | `/signIn`           | Login user                     |
| POST   | `/refresh-token`    | Refresh access token           |
| POST   | `/resetPassword`    | Initiate password reset        |
| POST   | `/verify-OTP`       | Verify OTP for password reset  |
| POST   | `/set-new-password` | Set new password after verification |
| GET    | `/verify-email/:token` | Verify email address        |
| GET    | `/check-verification/:email` | Check email verification status |

### Products
| Method | Endpoint                   | Description                     |
|--------|---------------------------|---------------------------------|
| GET    | `/get-all-products`       | Fetch all Dell and Lenovo products |
| GET    | `/get-product/:brand/:id` | Get a Dell or Lenovo product by brand and ID |

### Example Requests
#### SignUp
```http
POST /api/signUp
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}
```
#### Get Product
```http
GET /api/get-product/lenovo/123
```

## Error Handling
Standard HTTP status codes with JSON responses:
```json
{
  "success": false,
  "error": "Invalid OTP",
  "code": 400
}
```

### Common Error Codes:
- `400`: Bad Request
- `401`: Unauthorized
- `404`: Resource Not Found
- `500`: Internal Server Error

## Deployment
### Database
- PostgreSQL instance on AWS RDS
- Configured with proper security groups for Render IP access

### API
- Deployed as a Node.js application on Render
- Environment variables set in Render dashboard
- Automatic deployments from GitHub repository

## Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License
MIT License. See `LICENSE` for details.

## Contact
For questions or issues, contact `sikhumbuzobembe184@email.com` or open a GitHub issue.

## API URL
You can access the API here: `(https://e-commerce-rest-api-1-rqrw.onrender.com)`
