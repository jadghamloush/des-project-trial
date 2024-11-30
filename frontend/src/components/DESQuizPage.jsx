// src/components/DESQuizPage.js

import React, { useState, useEffect } from 'react';
import './DESQuizPage.css';

const DESQuizPage = () => {
  // Define multiple quizzes
  const quizzes = [
    {
      title: 'DES Basics Quiz',
      questions: [
        {
          question: 'What does DES stand for?',
          options: [
            'Data Encryption Standard',
            'Digital Encryption System',
            'Data Encoding Scheme',
            'Dynamic Encryption Service',
          ],
          answer: 'Data Encryption Standard',
        },
        {
          question: 'How many rounds does DES perform?',
          options: ['10', '12', '16', '20'],
          answer: '16',
        },
        {
          question: 'What is the key size used in DES?',
          options: ['56-bit', '64-bit', '128-bit', '256-bit'],
          answer: '56-bit',
        },
        {
          question: 'Which network structure does DES use?',
          options: [
            'Substitution-Permutation Network',
            'Feistel Network',
            'Block Cipher Network',
            'Stream Cipher Network',
          ],
          answer: 'Feistel Network',
        },
        {
          question: 'Why is DES no longer considered secure?',
          options: [
            'Small key size',
            'Slow encryption speed',
            'Complex algorithm',
            'Lack of support',
          ],
          answer: 'Small key size',
        },
      ],
    },
    {
      title: 'DES Cryptanalysis Quiz',
      questions: [
        {
          question: 'What is the primary method used to break DES?',
          options: ['Linear Cryptanalysis', 'Differential Cryptanalysis', 'Brute Force Attack', 'Side-Channel Attack'],
          answer: 'Brute Force Attack',
        },
        {
          question: 'Approximately how many possible keys exist for DES?',
          options: [
            '2^56',
            '2^64',
            '2^128',
            '2^256',
          ],
          answer: '2^56',
        },
        {
          question: 'Which organization officially replaced DES with a more secure algorithm?',
          options: ['ISO', 'NIST', 'IEEE', 'NSA'],
          answer: 'NIST',
        },
        {
          question: 'What is the name of the brute force attack machine that cracked DES in 1998?',
          options: [
            'Deep Crack',
            'CERNET',
            'DESBreaker',
            'Quantum Miner',
          ],
          answer: 'Deep Crack',
        },
        {
          question: 'What does the success of DES brute force attacks demonstrate?',
          options: [
            'DES is resistant to all attacks',
            'Short key lengths are vulnerable',
            'DES has a complex algorithm',
            'DES is suitable for high-security applications',
          ],
          answer: 'Short key lengths are vulnerable',
        },
      ],
    },
    {
      title: 'DES Advanced Quiz',
      questions: [
        {
          question: 'What padding scheme is commonly used with DES in CBC mode?',
          options: [
            'PKCS#7',
            'ISO 10126',
            'ANSI X.923',
            'All of the above',
          ],
          answer: 'All of the above',
        },
        {
          question: 'Which of the following is a variant of DES that uses multiple keys?',
          options: [
            'Triple DES (3DES)',
            'Advanced Encryption Standard (AES)',
            'Blowfish',
            'RC4',
          ],
          answer: 'Triple DES (3DES)',
        },
        {
          question: 'In DES, what is the purpose of the initial permutation (IP)?',
          options: [
            'Encrypt the plaintext',
            'Improve diffusion',
            'Rearrange the bits for processing',
            'Generate the subkeys',
          ],
          answer: 'Rearrange the bits for processing',
        },
        {
          question: 'How many subkeys are generated in DES for the 16 rounds?',
          options: ['16', '48', '64', '128'],
          answer: '16',
        },
        {
          question: 'Which step in DES increases the security by expanding the block size?',
          options: [
            'Initial Permutation',
            'Expansion Permutation',
            'Final Permutation',
            'Subkey Mixing',
          ],
          answer: 'Expansion Permutation',
        },
      ],
    },
    {
      title: 'DES Historical Quiz',
      questions: [
        {
          question: 'In which year was DES officially adopted as a federal standard?',
          options: ['1975', '1977', '1981', '1983'],
          answer: '1977',
        },
        {
          question: 'Which organization developed DES?',
          options: [
            'IBM',
            'Microsoft',
            'Apple',
            'Bell Labs',
          ],
          answer: 'IBM',
        },
        {
          question: 'What was the primary reason for developing DES?',
          options: [
            'To create a public-key encryption system',
            'To replace insecure existing encryption methods',
            'To develop a new hash function',
            'To provide a digital signature algorithm',
          ],
          answer: 'To replace insecure existing encryption methods',
        },
        {
          question: 'What cryptographic principle does DES primarily rely on?',
          options: [
            'Asymmetric Encryption',
            'Symmetric Encryption',
            'Hashing',
            'Steganography',
          ],
          answer: 'Symmetric Encryption',
        },
        {
          question: 'DES was succeeded by which algorithm as the new federal standard?',
          options: [
            'AES',
            'RSA',
            'SHA-256',
            'Blowfish',
          ],
          answer: 'AES',
        },
      ],
    },
    // Add more quizzes as needed
  ];

  // State to hold the list of available quizzes
  const [availableQuizzes, setAvailableQuizzes] = useState([...quizzes]);

  // State to hold the current quiz and question index
  const [currentQuiz, setCurrentQuiz] = useState(null);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [score, setScore] = useState(0);
  const [showScore, setShowScore] = useState(false);
  const [selectedOption, setSelectedOption] = useState(null);
  const [isCorrect, setIsCorrect] = useState(null);
  const [userAnswers, setUserAnswers] = useState([]);

  // Function to select a random quiz from available quizzes
  const selectRandomQuiz = () => {
    if (availableQuizzes.length === 0) {
      // Reset the available quizzes if all have been taken
      setAvailableQuizzes([...quizzes]);
    }
    const randomIndex = Math.floor(Math.random() * availableQuizzes.length);
    const selectedQuiz = availableQuizzes[randomIndex];
    // Remove the selected quiz from available quizzes
    setAvailableQuizzes(availableQuizzes.filter((quiz) => quiz !== selectedQuiz));
    return selectedQuiz;
  };

  // Initialize the first quiz on component mount
  useEffect(() => {
    const initialQuiz = selectRandomQuiz();
    setCurrentQuiz(initialQuiz);
  }, []);

  // Handler for option selection
  const handleOptionClick = (option) => {
    setSelectedOption(option);
    const correct = option === currentQuiz.questions[currentQuestion].answer;
    setIsCorrect(correct);
    if (correct) {
      setScore((prevScore) => prevScore + 1);
    }
    // Store user answer
    setUserAnswers([
      ...userAnswers,
      {
        question: currentQuiz.questions[currentQuestion].question,
        selected: option,
        correct: currentQuiz.questions[currentQuestion].answer,
      },
    ]);
  };

  // Handler to move to the next question or show score
  const handleNextQuestion = () => {
    setSelectedOption(null);
    setIsCorrect(null);
    const nextQuestion = currentQuestion + 1;
    if (nextQuestion < currentQuiz.questions.length) {
      setCurrentQuestion(nextQuestion);
    } else {
      setShowScore(true);
    }
  };

  // Handler to restart the quiz with a new random quiz
  const handleRestartQuiz = () => {
    const newQuiz = selectRandomQuiz();
    setCurrentQuiz(newQuiz);
    setCurrentQuestion(0);
    setScore(0);
    setShowScore(false);
    setSelectedOption(null);
    setIsCorrect(null);
    setUserAnswers([]);
  };

  // If the quiz hasn't been initialized yet
  if (!currentQuiz) {
    return (
      <div className="quiz-page-wrapper">
        <div className="des-quiz-page">
          <h2 className="quiz-title">DES Quiz</h2>
          <p>Loading quiz...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="quiz-page-wrapper">
      <div className="des-quiz-page">
        <h2 className="quiz-title">{currentQuiz.title}</h2>
        {showScore ? (
          <div className="score-section">
            <p>
              You scored {score} out of {currentQuiz.questions.length}
            </p>
            <button onClick={handleRestartQuiz} className="restart-button">
              Retake Quiz
            </button>
            <div className="detailed-results">
              {userAnswers.map((item, index) => (
                <div key={index} className="result-item">
                  <p>
                    <strong>Q{index + 1}: {item.question}</strong>
                  </p>
                  <p>Your Answer: {item.selected}</p>
                  <p>Correct Answer: {item.correct}</p>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="quiz-section">
            <div className="question-count">
              <span>Question {currentQuestion + 1}</span>/{currentQuiz.questions.length}
            </div>
            <div className="question-text">
              {currentQuiz.questions[currentQuestion].question}
            </div>
            <div className="options-container">
              {currentQuiz.questions[currentQuestion].options.map((option, index) => (
                <button
                  key={index}
                  className={`option-button ${
                    selectedOption === option
                      ? isCorrect
                        ? 'correct'
                        : 'incorrect'
                      : ''
                  }`}
                  onClick={() => handleOptionClick(option)}
                  disabled={selectedOption !== null}
                  aria-label={`Option ${index + 1}: ${option}`}
                >
                  {option}
                </button>
              ))}
            </div>
            {isCorrect !== null && (
              <div className={`feedback ${isCorrect ? 'correct' : 'incorrect'}`}>
                {isCorrect
                  ? '✅ Correct!'
                  : `❌ Incorrect! The correct answer is "${currentQuiz.questions[currentQuestion].answer}".`}
              </div>
            )}
            {selectedOption && (
              <button onClick={handleNextQuestion} className="next-button">
                {currentQuestion + 1 === currentQuiz.questions.length
                  ? 'See Results'
                  : 'Next Question'}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default DESQuizPage;
