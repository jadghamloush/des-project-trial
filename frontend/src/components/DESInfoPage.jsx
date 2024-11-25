import React from 'react';
import './DESInfoPage.css';

const DESInfoPage = () => {
  return (
    <div className="container des-info-page">
      <header className="header">
        <h1>Understanding DES (Data Encryption Standard)</h1>
        <p className="lead-text">
          DES is a symmetric-key block cipher that was widely used for data encryption in the 1970s and 1980s.
        </p>
      </header>

      <section className="section">
        <h2>What is DES?</h2>
        <p>
          The <strong>Data Encryption Standard (DES)</strong> is a symmetric-key block cipher, which means the same key is used for both encryption and decryption. 
          It was developed in the 1970s by IBM and adopted by the U.S. National Institute of Standards and Technology (NIST) as a federal standard for encryption. 
          DES encrypts data in 64-bit blocks, using a 56-bit key, and applies 16 rounds of encryption to each block.
        </p>
        <p>
          Despite being a widely used encryption standard for decades, DES is no longer considered secure due to advancements in computing power and cryptanalysis.
        </p>
      </section>

      <section className="section">
        <h2>How Does DES Work?</h2>
        <p>
          DES follows the Feistel network structure, where data is split into two halves, and a series of substitutions and permutations are applied in each of the 16 rounds:
          <ul>
            <li><strong>Key Size</strong>: 56-bit key length (with 64 bits total, 8 bits are used for parity).</li>
            <li><strong>Rounds</strong>: 16 rounds of permutation and substitution are applied to the 64-bit block of data.</li>
            <li><strong>Block Size</strong>: DES operates on 64-bit blocks of data.</li>
          </ul>
        </p>
        <p>
          The encryption process is reversible, meaning the same key is used for both encryption and decryption. 
          However, DES is known for its speed but is vulnerable to brute-force attacks, which led to its replacement by the Advanced Encryption Standard (AES) in most modern systems.
        </p>
      </section>

      <section className="section resources">
        <h2>Educational Resources</h2>
        <div className="resource-list">
          <div className="resource-item">
            <h3>YouTube Video: Introduction to DES</h3>
            <a href="https://www.youtube.com/watch?v=j53iXhTSi_s" target="_blank" rel="noopener noreferrer">
              Watch Video
            </a>
          </div>
          <div className="resource-item">
            <h3>Article: A Deep Dive into DES</h3>
            <a href="https://www.tutorialspoint.com/cryptography/data_encryption_standard.htm" target="_blank" rel="noopener noreferrer">
              Read Article
            </a>
          </div>
          <div className="resource-item">
            <h3>Book: Cryptography and Network Security by William Stallings</h3>
            <a href="https://www.amazon.com/Cryptography-Network-Security-Principles-Applications/dp/0134444280" target="_blank" rel="noopener noreferrer">
              View on Amazon
            </a>
          </div>
          <div className="resource-item">
            <h3>Online Course: Cryptography Basics (Including DES)</h3>
            <a href="https://www.udemy.com/course/cryptography-and-system-security/?couponCode=LETSLEARNNOW" target="_blank" rel="noopener noreferrer">
              Enroll in Course
            </a>
          </div>
        </div>
      </section>
    </div>
  );
};

export default DESInfoPage;
