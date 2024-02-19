import React, { useState, useEffect } from 'react';
import { ethers } from 'ethers';
import AcademicReportVerificationABI from "./ABI/AcademicReportVerificationABI.json"

const contractAddress = '0x22E043cf134470aa1889C761363BaAF2eE3FC3e1';
const provider = new ethers.providers.Web3Provider(window.ethereum);
const signer = provider.getSigner();
const contract = new ethers.Contract(contractAddress, AcademicReportVerificationABI, signer);
// const ethers = require("ethers");

const SinglePageComponent = () => {
    const [issuerAddress, setIssuerAddress] = useState('');
    const [authorized, setAuthorized] = useState(false);
    const [studentId, setStudentId] = useState('');
    const [reportHash, setReportHash] = useState('');
    const [issuanceDate, setIssuanceDate] = useState('');
    const [issuer, setIssuer] = useState('');
    const [zkProof, setZkProof] = useState('');
    const [reportId, setReportId] = useState('');
    const [verificationResult, setVerificationResult] = useState(null);
    const [revocationStatus, setRevocationStatus] = useState(null);
const initializeEthers = () => {
    provider = new ethers.providers.Web3Provider(window.ethereum);
    signer = provider.getSigner();
    contract = new ethers.Contract(contractAddress, AcademicReportVerificationABI.abi, signer);
};
    // Authorize Issuer
    const authorizeIssuer = async () => {
        await contract.setIssuerAuthorization(issuerAddress, authorized);
    };

    // Issue Report
    const issueReport = async () => {
        await contract.issueReport(
            ethers.utils.formatBytes32String(studentId),
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(reportHash)),
            Number(issuanceDate),
            issuer,
            ethers.utils.formatBytes32String(zkProof)
        );
    };

    // Revoke Report
    const revokeReport = async () => {
        await contract.revokeReport(ethers.utils.formatBytes32String(reportId));
    };

    // Check Revocation Status
    const checkRevocationStatus = async () => {
        const status = await contract.isReportRevoked(ethers.utils.formatBytes32String(reportId));
        setRevocationStatus(status);
    };

    // Verify Report
    const verifyReport = async () => {
        // Simplified example, adjust based on your proof structure
        const a = [ethers.BigNumber.from('0'), ethers.BigNumber.from('0')];
        const b = [[ethers.BigNumber.from('0'), ethers.BigNumber.from('0')], [ethers.BigNumber.from('0'), ethers.BigNumber.from('0')]];
        const c = [ethers.BigNumber.from('0'), ethers.BigNumber.from('0')];
        const input = [0, 0, 0]; // Example input, adjust accordingly

        const result = await contract.verifyReport(
            ethers.utils.formatBytes32String(reportId),
            a,
            b,
            c,
            input
        );
        setVerificationResult(result);
    };

    return (
        <div className="max-w-4xl mx-auto py-8">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* Authorize Issuer */}
                <div className="border p-4 rounded">
                    <h2 className="text-lg mb-4">Authorize Issuer</h2>
                    <input
                        className="border rounded w-full mb-2 p-2"
                        placeholder="Issuer Address"
                        value={issuerAddress}
                        onChange={(e) => setIssuerAddress(e.target.value)}
                    />
                    <button
                        className="bg-blue-500 text-white rounded p-2 w-full"
                        onClick={authorizeIssuer}
                    >
                        Authorize/Revoke Issuer
                    </button>
                </div>
    
                {/* Issue Report */}
                <div className="border p-4 rounded">
                    <h2 className="text-lg mb-4">Issue Report</h2>
                    {/* Similar input fields for studentId, reportHash, issuanceDate, issuer, zkProof */}
                    <button
                        className="bg-green-500 text-white rounded p-2 w-full"
                        onClick={issueReport}
                    >
                        Issue Report
                    </button>
                </div>
    
                {/* Revoke Report */}
                <div className="border p-4 rounded">
                    <h2 className="text-lg mb-4">Revoke Report</h2>
                    <input
                        className="border rounded w-full mb-2 p-2"
                        placeholder="Report ID"
                        value={reportId}
                        onChange={(e) => setReportId(e.target.value)}
                    />
                    <button
                        className="bg-red-500 text-white rounded p-2 w-full"
                        onClick={revokeReport}
                    >
                        Revoke Report
                    </button>
                </div>
    
                {/* Check Revocation Status */}
                <div className="border p-4 rounded">
                    <h2 className="text-lg mb-4">Check Revocation Status</h2>
                    {/* Reuse Report ID input field from Revoke Report */}
                    <button
                        className="bg-yellow-500 text-white rounded p-2 w-full"
                        onClick={checkRevocationStatus}
                    >
                        Check Status
                    </button>
                    {revocationStatus !== null && <p>Status: {revocationStatus ? 'Revoked' : 'Not Revoked'}</p>}
                </div>
    
                {/* Verify Report */}
                <div className="border p-4 rounded">
                    <h2 className="text-lg mb-4">Verify Report</h2>
                    {/* Simplified for demonstration; you would need additional inputs for a, b, c, and input */}
                    <button
                        className="bg-purple-500 text-white rounded p-2 w-full"
                        onClick={verifyReport}
                    >
                        Verify Report
                    </button>
                    {verificationResult !== null && <p>Verification Result: {verificationResult ? 'Verified' : 'Not Verified'}</p>}
                </div>
            </div>
        </div>
    );
    
};

export default SinglePageComponent;
