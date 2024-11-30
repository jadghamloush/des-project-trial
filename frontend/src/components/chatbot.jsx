import React, { useState } from "react";
import "./chatbot.css"; // Add this for styling

const Chatbot = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");

  const handleToggleChat = () => {
    setIsOpen(!isOpen);

    // Add the initial bot message when the chat opens for the first time
    if (!isOpen && messages.length === 0) {
      setMessages([
        { sender: "bot", content: "Hello, how can I help you today?\nType close when you finish." },
      ]);
    }
  };

  const sendMessage = async () => {
    if (input.trim() === "") return;

    // Add the user's message to the chat
    setMessages((prevMessages) => [
      ...prevMessages,
      { sender: "user", content: input },
    ]);

    try {
      const response = await fetch("http://localhost:5000/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: input }), // Send user input to the backend
      });

      const data = await response.json();
      if (response.ok) {
        // Add the bot's response to the chat
        setMessages((prevMessages) => [
          ...prevMessages,
          { sender: "bot", content: data.response },
        ]);
      } else {
        setMessages((prevMessages) => [
          ...prevMessages,
          { sender: "bot", content: "Error: " + data.response },
        ]);
      }
    } catch (error) {
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: "bot", content: "Error connecting to the server." },
      ]);
    }

    setInput(""); // Clear input field
  };

  return (
    <>
      <button className="chatbot-button" onClick={handleToggleChat}>
        💬
      </button>

      {isOpen && (
        <div className="chatbot">
          <div className="chatbot-header">
            <h3>Chatbot</h3>
            <button className="close-button" onClick={handleToggleChat}>
              ✖
            </button>
          </div>
          <div className="chatbot-messages">
            {messages.map((msg, index) => (
              <div
                key={index}
                className={`message ${
                  msg.sender === "user" ? "user-message" : "bot-message"
                }`}
              >
                {msg.content}
              </div>
            ))}
          </div>
          <div className="chatbot-input">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type a message..."
            />
            <button onClick={sendMessage}>Send</button>
          </div>
        </div>
      )}
    </>
  );
};

export default Chatbot;
