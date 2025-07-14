const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const PROTO_PATH = './proto/todo.proto';
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const todoProto = grpc.loadPackageDefinition(packageDefinition).todo;

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'mysql',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'todolist',
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to verify JWT token
async function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    if (rows.length === 0) throw new Error('User not found');
    return decoded;
  } catch (err) {
    throw new Error('Invalid token');
  }
}

async function Register(call, callback) {
  const { username, password } = call.request;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    callback(null, { message: 'User registered successfully', success: true });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function Login(call, callback) {
  const { username, password } = call.request;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return callback(null, { message: 'User not found', success: false });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return callback(null, { message: 'Invalid password', success: false });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    callback(null, { token, success: true, message: 'Login successful' });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function CreateTodo(call, callback) {
  const { token, title, description } = call.request;
  try {
    const decoded = await verifyToken(token);
    const [result] = await pool.query(
      'INSERT INTO todos (user_id, title, description) VALUES (?, ?, ?)',
      [decoded.userId, title, description]
    );
    callback(null, {
      todo: { id: result.insertId, title, description, completed: false },
      success: true,
      message: 'Todo created',
    });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function GetTodos(call, callback) {
  const { token } = call.request;
  try {
    const decoded = await verifyToken(token);
    const [rows] = await pool.query('SELECT * FROM todos WHERE user_id = ?', [decoded.userId]);
    callback(null, { todos: rows, success: true, message: 'Todos retrieved' });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function UpdateTodo(call, callback) {
  const { token, id, title, description, completed } = call.request;
  try {
    const decoded = await verifyToken(token);
    await pool.query(
      'UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ? AND user_id = ?',
      [title, description, completed, id, decoded.userId]
    );
    callback(null, { todo: { id, title, description, completed }, success: true, message: 'Todo updated' });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function DeleteTodo(call, callback) {
  const { token, id } = call.request;
  try {
    const decoded = await verifyToken(token);
    await pool.query('DELETE FROM todos WHERE id = ? AND user_id = ?', [id, decoded.userId]);
    callback(null, { todo: { id }, success: true, message: 'Todo deleted' });
  } catch (err) {
    callback(null, { message: err.message, success: false });
  }
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS todos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      completed BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
}

const server = new grpc.Server();
server.addService(todoProto.TodoService.service, {
  Register,
  Login,
  CreateTodo,
  GetTodos,
  UpdateTodo,
  DeleteTodo,
});

server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), async (err, port) => {
  if (err) {
    console.error(err);
    return;
  }
  await initializeDatabase();
  server.start();
  console.log(`Server running at 0.0.0.0:${port}`);
});