const express = require('express');
require('dotenv').config();
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// --- Session Setup ---
const sessionMiddleware = session({
    secret: 'YOUR_SESSION_SECRET', // REPLACE THIS with a strong, random string
    resave: false, // Recommended: do not resave session if not modified
    saveUninitialized: false, // Recommended: do not save uninitialized sessions
    cookie: { secure: false } // Set to true in production with HTTPS
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Google Strategy ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://real-time-chat-w5t8.onrender.com/auth/google/callback'
},
function(accessToken, refreshToken, profile, cb) {
    console.log('Google Profile received:', profile);
    return cb(null, profile);
}));

// --- Passport Serialization/Deserialization ---
// How to store user in session
passport.serializeUser((user, done) => {
    const serializedUser = { id: user.id, displayName: user.displayName, photo: user.photos && user.photos.length > 0 ? user.photos[0].value : null };
    console.log('Serializing user:', serializedUser);
    done(null, serializedUser); // Store Google ID, display name, and photo in session
});

// How to retrieve user from session
passport.deserializeUser((user, done) => {
    console.log('Deserializing user:', user);
    done(null, user);
});

// --- Authentication Routes ---
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Successful authentication, redirect to chat page
        res.redirect('/chat.html');
    });

// --- Middleware to check if user is authenticated ---
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/'); // Redirect to login/home if not authenticated
}

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
});

// Protect your chat page
app.get('/chat.html', ensureAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/index.html'); // Serve your chat UI
});

// Serve other static files from public directory
app.use(express.static(__dirname + '/public'));

// --- Socket.IO Logic ---
// Make session available to Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

let connectedUsers = {}; // Maps Google ID to { socketId: string, displayName: string }
let userRooms = {}; // Maps userId to an array of roomIds they are in
let chatHistory = {}; // Maps roomId to an array of message objects

function emitOnlineUsers() {
    const onlineUsers = Object.keys(connectedUsers).map(userId => ({
        id: userId,
        displayName: connectedUsers[userId].displayName,
        photo: connectedUsers[userId].photo
    }));
    io.emit('online_users', onlineUsers);
}

io.on('connection', (socket) => {
    const userId = socket.request.session.passport ? socket.request.session.passport.user.id : null;

    if (!userId) {
        console.log('Unauthenticated user tried to connect. Disconnecting.');
        socket.emit('auth_required', 'Please log in with Google to join the chat.');
        socket.disconnect(true);
        return;
    }

    const userDisplayName = socket.request.session.passport ? socket.request.session.passport.user.displayName : userId;
    const userPhoto = socket.request.session.passport ? socket.request.session.passport.user.photo : null;
    connectedUsers[userId] = { socketId: socket.id, displayName: userDisplayName, photo: userPhoto }; // Store socket ID, display name, and photo for this user
    userRooms[userId] = userRooms[userId] || []; // Initialize rooms for user if not exists
    // Send the authenticated user's ID to the client
    socket.emit('authenticated_id', userId);

    console.log(`User ${userId} (${socket.request.session.passport.user.displayName}) connected.`);
    emitOnlineUsers();

    // Event to initiate a private chat
    socket.on('initiate_private_chat', (targetUserId) => {
        if (userId === targetUserId) {
            socket.emit('chat_error', 'Cannot initiate chat with yourself.');
            return;
        }
        if (!connectedUsers[targetUserId]) {
            socket.emit('chat_error', 'Target user is not online.');
            return;
        }

        // Create a unique room ID for the two users (sorted to ensure consistency)
        const participants = [userId, targetUserId].sort();
        const roomId = `private_${participants[0]}_${participants[1]}`;

        // Make both users join the room
        socket.join(roomId);
        const targetSocket = io.sockets.sockets.get(connectedUsers[targetUserId].socketId);
        if (targetSocket) {
            targetSocket.join(roomId);
        }

        // Add room to userRooms for both participants
        if (!userRooms[userId].includes(roomId)) {
            userRooms[userId].push(roomId);
        }
        if (targetSocket && !userRooms[targetUserId].includes(roomId)) {
            userRooms[targetUserId].push(roomId);
        }

        // Initialize chat history for the room if it doesn't exist
        if (!chatHistory[roomId]) {
            chatHistory[roomId] = [];
        }

        console.log(`Private chat initiated between ${userId} and ${targetUserId} in room: ${roomId}`);
        io.to(roomId).emit('private_chat_initiated', { 
            roomId: roomId, 
            participants: participants,
            history: chatHistory[roomId]
        });
    });

    socket.on('chat message', (data) => {
        console.log(`Server received chat message from ${userId}:`, data);
        // data can contain { message: string, file: string, fileName: string, fileType: string, roomId: string }
        if (data.roomId && socket.rooms.has(data.roomId)) {
            const messageData = {
                senderId: userId,
                senderDisplayName: userDisplayName,
                senderPhoto: userPhoto,
                roomId: data.roomId
            };

            if (data.message) {
                messageData.message = data.message;
            } else if (data.file) {
                messageData.file = data.file;
                messageData.fileName = data.fileName;
                messageData.fileType = data.fileType;
            }

            // Store the message in history
            if (!chatHistory[data.roomId]) {
                chatHistory[data.roomId] = [];
            }
            chatHistory[data.roomId].push(messageData);

            console.log(`Server emitting chat message to room ${data.roomId}:`, messageData);
            io.to(data.roomId).emit('chat message', messageData);
        } else {
            console.warn(`Server: Invalid room or not joined to the room for user ${userId}. Data:`, data);
            socket.emit('chat_error', 'Invalid room or not joined to the room.');
        }
    });

    socket.on('disconnect', () => {
        console.log(`User ${userId} disconnected.`);
        delete connectedUsers[userId];
        emitOnlineUsers();

        // Make the user leave all rooms they were in
        if (userRooms[userId]) {
            userRooms[userId].forEach(roomId => {
                socket.leave(roomId);
            });
            delete userRooms[userId];
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
