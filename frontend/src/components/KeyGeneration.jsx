// frontend/src/components/KeyGeneration.js

import React, { useState } from "react";
import {
  Button,
  Card,
  Alert,
  Spinner,
  InputGroup,
  FormControl,
  Tabs,
  Tab,
} from "react-bootstrap";
import axios from "axios";
import "./KeyGeneration.css";

const KeyGeneration = () => {
  const [keyHex, setKeyHex] = useState("");
  const [keyBinary, setKeyBinary] = useState("");
  const [keyBase64, setKeyBase64] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const generateKey = async () => {
    setError("");
    setLoading(true);
    try {
      const response = await axios.get("https://flask-alb-1611654522.us-east-2.elb.amazonaws.com/generate_key");
      if (response.data.key_hex && response.data.key_binary) {
        setKeyHex(response.data.key_hex);
        setKeyBinary(response.data.key_binary);
        setKeyBase64(response.data.key_base64);
      } else {
        setError("Failed to generate key.");
      }
    } catch (err) {
      setError("An error occurred while generating the key.");
      console.error(err);
    }
    setLoading(false);
  };

  const copyToClipboard = (text, format) => {
    navigator.clipboard.writeText(text).then(
      () => {
        alert(`${format} key copied to clipboard!`);
      },
      (err) => {
        console.error("Could not copy text: ", err);
      }
    );
  };

  const downloadKey = (text, format) => {
    const element = document.createElement("a");
    const file = new Blob([text], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = `key_${format}.${format === "hex" ? "txt" : format}`;
    document.body.appendChild(element); // Required for this to work in FireFox
    element.click();
    document.body.removeChild(element); // Clean up
  };

  return (
    <div className="key-generation-container">
      <Card className="shadow-lg p-5 mb-4 key-generation-card">
        <h2 className="text-center text-primary mb-4">Random Key Generation</h2>
        <div className="d-flex justify-content-center mt-3">
          <Button
            variant="primary"
            onClick={generateKey}
            disabled={loading}
            className="generate-btn"
          >
            {loading ? (
              <>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Generating...
              </>
            ) : (
              "Generate Key"
            )}
          </Button>
        </div>
        {error && (
          <Alert variant="danger" className="mt-3 text-center">
            {error}
          </Alert>
        )}
        {keyHex && (
           <div className="mt-4">
           {/* Hexadecimal Key */}
           <div className="row align-items-center mt-3">
             <span className="col-auto fw-bold larger-text">Hexadecimal:</span>
             <div className="col">
               <InputGroup>
                 <FormControl
                   type="text"
                   value={keyHex}
                   readOnly
                   className="text-center key-display"
                   placeholder="Hexadecimal Key"
                 />
                 <Button
                   variant="outline-secondary"
                   onClick={() => copyToClipboard(keyHex, "Hexadecimal")}
                   className="copy-btn"
                 >
                   Copy
                 </Button>
                 <Button
                   variant="outline-secondary"
                   onClick={() => downloadKey(keyHex, "hex")}
                   className="download-btn"
                 >
                   Download
                 </Button>
               </InputGroup>
             </div>
           </div>
   
           {/* Binary Key */}
           <div className="row align-items-center mt-3">
             <span className="col-auto fw-bold larger-text">Binary:</span>
             <div className="col">
               <InputGroup>
                 <FormControl
                   type="text"
                   value={keyBinary}
                   readOnly
                   className="text-center key-display"
                   placeholder="Binary Key"
                 />
                 <Button
                   variant="outline-secondary"
                   onClick={() => copyToClipboard(keyBinary, "Binary")}
                   className="copy-btn"
                 >
                   Copy
                 </Button>
                 <Button
                   variant="outline-secondary"
                   onClick={() => downloadKey(keyBinary, "binary")}
                   className="download-btn"
                 >
                   Download
                 </Button>
               </InputGroup>
             </div>
           </div>

           {/* Base64 Key */}
           <div className="row align-items-center mt-3">
             <span className="col-auto fw-bold larger-text">Base64:</span>
             <div className="col">
               <InputGroup>
                 <FormControl
                   type="text"
                   value={keyBase64}
                   readOnly
                   className="text-center key-display"
                   placeholder="Base64 Key"
                 />
                 <Button
                   variant="outline-secondary"
                   onClick={() => copyToClipboard(keyBase64, "Base64")}
                   className="copy-btn"
                 >
                   Copy
                 </Button>
                 <Button
                   variant="outline-secondary"
                   onClick={() => downloadKey(keyBase64, "base64")}
                   className="download-btn"
                 >
                   Download
                 </Button>
               </InputGroup>
             </div>
           </div>
         </div>
           )}
      </Card>
    </div>
  );
};

export default KeyGeneration;
