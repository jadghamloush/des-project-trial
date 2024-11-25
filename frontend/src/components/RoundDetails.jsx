// src/components/RoundDetails.jsx

import React from 'react';
import { Accordion, Table, OverlayTrigger, Tooltip } from 'react-bootstrap';
import PropTypes from 'prop-types';
import './RoundDetails.css';

const RoundDetails = React.memo(({ rounds, processType }) => {
  console.log("Received Rounds:", rounds); // Debugging

  if (!rounds || !Array.isArray(rounds)) {
    return <div className="text-center">No round details available.</div>;
  }

  return (
    <div className="mt-4">
      <h3 className="round-details-header">{processType} Round Information</h3>
      <Accordion defaultActiveKey="0" className="detailed-round-accordion">
        {rounds.map((round) => {
          console.log(`Round ${round.round} Data:`, round); // Debugging
          return (
            <Accordion.Item
              eventKey={round.round.toString()}
              key={round.round}
              className="accordion-item"
            >
              <Accordion.Header className="accordion-header">
                <strong>{processType} Round {round.round}</strong>
              </Accordion.Header>
              <Accordion.Body className="accordion-body">
                {round.subkey && round.expanded_right && round.xor_with_subkey ? (
                  <Table striped bordered hover size="sm" responsive>
                    <thead>
                      <tr>
                        <th>Step</th>
                        <th>Description</th>
                        <th>Output</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* Step 1: Subkey Generation */}
                      <tr>
                        <td>1. Subkey Generation</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-subkey-${round.round}`} className="custom-tooltip">
                                Subkey is derived from the main key using key scheduling.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Subkey for this round</span>
                          </OverlayTrigger>
                        </td>
                        <td>{round.subkey.join('')}</td>
                      </tr>

                      {/* Step 2: Expansion (E) */}
                      <tr>
                        <td>2. Expansion (E)</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-expansion-${round.round}`} className="custom-tooltip">
                                Expands the 32-bit right half to 48 bits.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Expanded Right Half</span>
                          </OverlayTrigger>
                        </td>
                        <td>{round.expanded_right.join('')}</td>
                      </tr>

                      {/* Step 3: XOR with Subkey */}
                      <tr>
                        <td>3. XOR with Subkey</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-xor-${round.round}`} className="custom-tooltip">
                                Performs a bitwise XOR between the expanded right half and the subkey.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Result of XORing E(R) with Subkey</span>
                          </OverlayTrigger>
                        </td>
                        <td>{round.xor_with_subkey.join('')}</td>
                      </tr>

                      {/* Step 4: S-Box Substitution */}
                      <tr>
                        <td>4. S-Box Substitution</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-sbox-${round.round}`} className="custom-tooltip">
                                Applies S-boxes to reduce 48 bits back to 32 bits.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Output after S-box substitutions</span>
                          </OverlayTrigger>
                        </td>
                        <td>
                          {round.sbox_details && round.sbox_details.length > 0 ? (
                            round.sbox_details.map((sbox, index) => (
                              <div key={index}>
                                <strong>{sbox.sbox}:</strong> {sbox.input} → {sbox.output}
                              </div>
                            ))
                          ) : (
                            'No S-box details available.'
                          )}
                        </td>
                      </tr>

                      {/* Step 5: Permutation (P) */}
                      <tr>
                        <td>5. Permutation (P)</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-permutation-${round.round}`} className="custom-tooltip">
                                Permutes the bits to increase diffusion.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Permutation of S-box Output</span>
                          </OverlayTrigger>
                        </td>
                        <td>{round.permutation_output.join('')}</td>
                      </tr>

                      {/* Step 6: XOR with Left Half */}
                      <tr>
                        <td>6. XOR with Left Half</td>
                        <td>
                          <OverlayTrigger
                            placement="top"
                            overlay={
                              <Tooltip id={`tooltip-final-xor-${round.round}`} className="custom-tooltip">
                                Final XOR between the permuted output and the left half.
                              </Tooltip>
                            }
                          >
                            <span className="tooltip-trigger">Result of XORing P(S-box Output) with Left Half</span>
                          </OverlayTrigger>
                        </td>
                        <td>{round.right_after.join('')}</td>
                      </tr>
                    </tbody>
                  </Table>
                ) : (
                  <p className="text-center text-warning">Round data is incomplete.</p>
                )}
              </Accordion.Body>
            </Accordion.Item>
          );
        })}
      </Accordion>
    </div>
  );
});

RoundDetails.propTypes = {
  rounds: PropTypes.arrayOf(
    PropTypes.shape({
      round: PropTypes.number.isRequired,
      subkey: PropTypes.arrayOf(PropTypes.number).isRequired,
      expanded_right: PropTypes.arrayOf(PropTypes.number).isRequired,
      xor_with_subkey: PropTypes.arrayOf(PropTypes.number).isRequired,
      sbox_details: PropTypes.arrayOf(
        PropTypes.shape({
          sbox: PropTypes.string.isRequired,
          input: PropTypes.string.isRequired,
          row: PropTypes.number.isRequired,
          column: PropTypes.number.isRequired,
          output: PropTypes.string.isRequired,
        })
      ).isRequired,
      permutation_output: PropTypes.arrayOf(PropTypes.number).isRequired,
      left_after: PropTypes.arrayOf(PropTypes.number).isRequired,
      right_after: PropTypes.arrayOf(PropTypes.number).isRequired,
    })
  ).isRequired,
  processType: PropTypes.string.isRequired, // 'Encryption' or 'Decryption'
};

RoundDetails.defaultProps = {
  processType: 'Encryption',
};

export default RoundDetails;
