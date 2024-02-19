// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./Verifier.sol";

contract AcademicReportVerification {
    struct AcademicReport {
        bytes32 reportHash;
        uint issuanceDate;
        bool revoked;
        string issuer;
        bytes32 zkProof; // Placeholder for zk-SNARK proof for course completion without revealing grades
    }

    address private owner;
    Verifier private verifier; // Instance of the Verifier contract

    mapping(address => bool) private authorizedIssuers;
    mapping(bytes32 => AcademicReport) private reports;

    event ReportIssued(bytes32 indexed reportId, string issuer, uint issuanceDate);
    event ReportRevoked(bytes32 indexed reportId);

    modifier onlyOwner() {
        require(msg.sender == owner, "This action is restricted to the owner.");
        _;
    }

    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender], "This action is restricted to authorized issuers.");
        _;
    }

    constructor() {
        owner = msg.sender;
        verifier = Verifier(0xd9145CCE52D386f254917e481eB44e9943F39138); // Initialize Verifier instance

    }

    // Owner can authorize or revoke issuer rights
    function setIssuerAuthorization(address issuer, bool authorized) external onlyOwner {
        authorizedIssuers[issuer] = authorized;
    }

    function checkIssuerStatus (address issuer) public view returns (bool) {
        return authorizedIssuers[issuer];
    }

    // Issue a new academic report
    function issueReport(bytes32 studentId, bytes32 reportHash, uint issuanceDate, string calldata issuer, bytes32 zkProof) external onlyAuthorizedIssuer {
        bytes32 reportId = keccak256(abi.encodePacked(studentId, reportHash, issuanceDate));
        require(reports[reportId].issuanceDate == 0, "Report already issued.");

        reports[reportId] = AcademicReport({
            reportHash: reportHash,
            issuanceDate: issuanceDate,
            revoked: false,
            issuer: issuer,
            zkProof: zkProof
        });

        emit ReportIssued(reportId, issuer, issuanceDate);
    }

    // Revoke an academic report
    function revokeReport(bytes32 reportId) external onlyAuthorizedIssuer {
        require(reports[reportId].issuanceDate != 0, "Report does not exist.");
        reports[reportId].revoked = true;

        emit ReportRevoked(reportId);
    }

    // Check if a report is revoked
    function isReportRevoked(bytes32 reportId) external view returns (bool) {
        require(reports[reportId].issuanceDate != 0, "Report does not exist.");
        return reports[reportId].revoked;
    }

    // Verify report using zk-SNARK proof 
   function verifyReport(
    bytes32 reportId, 
    uint[2] memory a,
    uint[2][2] memory b,
    uint[2] memory c,
    uint[3] memory input
) public view returns (bool) {
    require(reports[reportId].issuanceDate != 0, "Report does not exist.");

    Pairing.G1Point memory pointA = Pairing.G1Point(a[0], a[1]);
    Pairing.G2Point memory pointB = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
    Pairing.G1Point memory pointC = Pairing.G1Point(c[0], c[1]);

    Verifier.Proof memory proof = Verifier.Proof({
        a: pointA,
        b: pointB,
        c: pointC
    });

    bool verified = verifier.verifyTx(proof, input);
    return verified && !reports[reportId].revoked;
}
}
