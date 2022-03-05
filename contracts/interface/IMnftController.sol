// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMnftController {
    struct SupportPayment {
        address token;
        string symbol;
        bool status;
    }

    function feeTo() external view returns(address);
    function sigAddress() external view returns(address);
    function creaters(uint256) external view returns(address);
    function supportPayments(address) external view returns(SupportPayment memory);

    function getFees(
        uint256 _price,
        uint256 _authorProtocolFee
    ) external view returns(uint256 totalFee, uint256 txFee, uint256 authorFee);
    function getMaximumFee(uint256 _price) external view returns(uint256 maximumFee);

    function isSigAddress(address _addr) external view returns(bool);
    function isSupportPayment(address _paymentToken) external view returns(bool isSupport);
    function mint(address _to, uint256 _tokenId, uint256 _amount, bytes memory _data) external;
}