const socket = require("socket.io");
const crypto = require("crypto");
const Chat = require("../models/chat");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");
const User = require("../models/user");
const ConnectionRequest = require("../models/connectionRequest");

const getSecretRoomId = (userId, targetUserId) => {
  return crypto
    .createHash("sha256")
    .update([userId, targetUserId].sort().join("|"))
    .digest("hex");
};

const initializeSocket = (server) => {
  const io = socket(server, {
    cors: {
      origin: "http://localhost:5173",
      credentials: true,
    },
  });

  //middleware to userId
  io.use(async (socket, next) => {
    try {
      const cookieHeader = socket.handshake.headers.cookie;
      if (!cookieHeader) {
        return next(new Error("No cookies found"));
      }
      const parsed = cookie.parse(cookieHeader);
      const token = parsed.token;

      if (!token) {
        return next(new Error("No token found"));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await User.findById(decoded._id);
      if (!user) return next(new Error("User not found"));

      socket.user = user;

      next();
    } catch (err) {
      next(new Error("Auth failed"));
    }
  });

  io.on("connection", (socket) => {
    //handle events
    socket.on("joinChat", ({ targetUserId }) => {
      const userId = socket.user._id;
      const roomId = getSecretRoomId(userId, targetUserId);

      socket.join(roomId);
    });

    socket.on("sendMessage", async ({ targetUserId, firstName, text }) => {
      try {
        const userId = socket.user._id;
        const roomId = getSecretRoomId(userId, targetUserId);

        //check if the users are connections or not
        const connection = await ConnectionRequest.findOne({
          $or: [
            { fromUserId: userId, toUserId: targetUserId, status: "accepted" },
            { fromUserId: targetUserId, toUserId: userId, status: "accepted" },
          ],
        });
        if (!connection) {
          console.log("Users are not connected");
          return;
        }

        //save the message to db
        let chat = await Chat.findOne({
          participants: { $all: [userId, targetUserId] },
        });

        if (!chat) {
          chat = new Chat({
            participants: [userId, targetUserId],
            messages: [],
          });
        }

        chat.messages.push({
          senderId: userId,
          text,
        });

        await chat.save();

        //get the latest message from db
        const latestMessage = chat.messages[chat.messages.length - 1];

        io.to(roomId).emit("messageRecieved", {
          firstName,
          text,
          createdAt: latestMessage.createdAt,
        });
      } catch (err) {
        console.log(err);
      }
    });
  });
};

module.exports = initializeSocket;
