// SPDX-License-Identifier: MIT

pragma solidity ^0.8.10;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./utils/Validation.sol";
import "./interface/IOpenmetaController.sol";
import "./libraries/TransferHelper.sol";

abstract contract TradeModel is EIP712{
    bytes32 public constant MAKER_ORDER_TYPEHASH    =   keccak256(
        "MakerOrder(bytes32 nftTokenHash,address maker,uint256 price,uint256 quantity,address paymentToken,uint256 authorProtocolFee,uint8 saleType,uint256 startTime,uint256 endTime,uint256 createTime,uint256 cancelTime)"
    );
    bytes32 public constant TAKER_ORDER_TYPEHASH    =   keccak256(
        "DealOrder(bytes32 makerOrderHash,address taker,address author,uint256 dealAmount,uint256 rewardAmount,uint256 salt,bool minted,uint256 deadline,uint256 createTime)"
    );
    bytes32 public constant DEAL_ORDER_TYPEHASH    =   keccak256(
        "DealOrder(bytes32 makerOrderHash,address taker,address author,uint256 dealAmount,uint256 rewardAmount,uint256 salt,bool minted,uint256 deadline,uint256 createTime,bytes takerSig)"
    );

    enum TokenType{ TYPE_BASE, TYPE_ERC721, TYPE_ERC1155 }
    enum SaleType{ TYPE_BASE, TYPE_MARKET, TYPE_AUCTION }

    struct NftInfo {
        address nftToken;           // The NFT contract address of the transaction
        uint256 tokenId;            // The tokenid of the NFT contract address
        TokenType tokenType;        // Order nft token type: ERC721 or ERC1155
        uint256 chainId;
        uint256 salt;
    }

    struct MakerOrder {
        bytes32 nftTokenHash;       // Struct NftInfo hash
        address maker;              // Maker's address for the order
        uint256 price;              // The price of the order
        uint256 quantity;           // Quantity of the order NFT sold
        address paymentToken;       // Token address for payment
        uint256 authorProtocolFee;  // Copyright fees for NFT authors
        SaleType saleType;          // Order trade type: Market or Auction
        uint256 startTime;          // Sales start time
        uint256 endTime;            // Sales end time
        uint256 createTime;
        uint256 cancelTime;
        bytes signature;
    }

    struct DealOrder {
        bytes32 makerOrderHash;     // Maker order hash
        address taker;              // Taker's address for the order
        address author;             // NFT author address
        uint256 dealAmount;         // The final transaction amount of the order
        uint256 rewardAmount;       // Reward amount returned by holding coins
        uint256 salt;
        bool minted;                // Whether the NFT has been minted
        uint256 deadline;           // Deal order deadline
        uint256 createTime;
        bytes takerSig;             // Taker's address signature
        bytes signature;            // Operator address signature
    }

    function getOrderHashBySig (
        NftInfo memory _nftInfo, 
        MakerOrder memory _makerOrder, 
        DealOrder memory _dealOrder, 
        IOpenmetaController _controller
    ) view internal returns(bytes32 dealOrderHash) {
        bytes32 makerOrderHash = _makerOrderSig(_nftInfo, _makerOrder);
        require(makerOrderHash == _dealOrder.makerOrderHash, "maker order hash does not match");

        _takerOrderSig(_dealOrder);
        dealOrderHash = _dealOrderSig(_dealOrder, _controller);
    }

    function _makerOrderSig(NftInfo memory _nftInfo, MakerOrder memory _order) view private returns(bytes32 makerOrderHash) {
        bytes32 nftTokenHash = keccak256(abi.encodePacked(
            _nftInfo.nftToken, 
            _nftInfo.tokenId, 
            _nftInfo.tokenType, 
            block.chainid, 
            _nftInfo.salt
        ));
        require(nftTokenHash == _order.nftTokenHash, "Failed to verify nft token hash");

        makerOrderHash = _hashTypedDataV4(keccak256(abi.encode(
            MAKER_ORDER_TYPEHASH,
            nftTokenHash,
            _order.maker,
            _order.price,
            _order.quantity,
            _order.paymentToken,
            _order.authorProtocolFee,
            _order.saleType,
            _order.startTime,
            _order.endTime,
            _order.createTime,
            _order.cancelTime
        )));

        address signer = ECDSA.recover(makerOrderHash, _order.signature);
        require(signer == _order.maker, "Failed to verify maker signature");
    }

    function _takerOrderSig(DealOrder memory _order) view private {
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            TAKER_ORDER_TYPEHASH,
            _order.makerOrderHash,
            _order.taker,
            _order.author,
            _order.dealAmount,
            _order.rewardAmount,
            _order.salt,
            _order.minted,
            _order.deadline,
            _order.createTime
        )));

        address signer = ECDSA.recover(digest, _order.takerSig);
        require(signer == _order.taker, "Failed to verify taker signature");
    }

    function _dealOrderSig(
        DealOrder memory _order, 
        IOpenmetaController _controller
    ) view private returns(bytes32 dealOrderHash) {
        dealOrderHash = _hashTypedDataV4(keccak256(abi.encode(
            DEAL_ORDER_TYPEHASH,
            _order.makerOrderHash,
            _order.taker,
            _order.author,
            _order.dealAmount,
            _order.rewardAmount,
            _order.salt,
            _order.minted,
            _order.deadline,
            _order.createTime,
            keccak256(_order.takerSig)
        )));
        address signer = ECDSA.recover(dealOrderHash, _order.signature);

        require(
            _controller.isSigAddress(signer), 
            "Failed to verify singer signature"
        );
    }
}

contract OpenmetaTrade is Validation, TradeModel {
    IOpenmetaController public controller;

    modifier checkOrderCaller( MakerOrder memory _makerOrder, DealOrder memory _dealOrder) {
        if (_makerOrder.saleType == SaleType.TYPE_AUCTION) {
            require(controller.isSigAddress(msg.sender), "caller is not the signer");
        } else {
            require(msg.sender == _dealOrder.taker, "caller is not the taker");
        }
        _;
    }

    event PerformOrder(
        bytes32 indexed makerOrderHash, 
        bytes32 indexed dealOrderHash, 
        SaleType saleType, 
        address maker, 
        address taker, 
        uint256 dealAmount, 
        uint256 totalFee, 
        bool orderRes
    );

    constructor(address _controller) EIP712("Openmeta NFT Trade", "2.0.0") {
        controller = IOpenmetaController(_controller);
    }

    function performOrder(NftInfo memory _nftInfo, MakerOrder memory _makerOrder, DealOrder memory _dealOrder) 
        payable 
        checkOrderCaller(_makerOrder, _dealOrder) 
        checkDeadline(_dealOrder.deadline)
        external 
        returns(bytes32 dealOrderHash, uint256 totalFee) 
    {
        require(controller.isSupportPayment(_makerOrder.paymentToken), "not support payment token");

        dealOrderHash = getOrderHashBySig(_nftInfo, _makerOrder, _dealOrder, controller);
        bool isOriginToken = controller.isOriginToken(_makerOrder.paymentToken);

        /// When the order type is auction, check whether the conditions are met. 
        /// If not, the transfer will not be processed and the event flag will be false
        bool processRes = true;
        if (_makerOrder.saleType == SaleType.TYPE_AUCTION) {
            (uint256 nftBalance, uint256 amountBalance) = getOrderUserBalance(_nftInfo, _makerOrder, _dealOrder.taker, isOriginToken);

            if (nftBalance < _makerOrder.quantity || amountBalance < _dealOrder.dealAmount) {
                processRes = false;
            }
        }

        /// If the conditions are met, initiate a transfer to complete the order transaction
        if (processRes) {
            totalFee = _transferForTakeFee(_nftInfo, _makerOrder, _dealOrder, isOriginToken);
        }

        emit PerformOrder(
            _dealOrder.makerOrderHash,
            dealOrderHash,
            _makerOrder.saleType,
            _makerOrder.maker,
            _dealOrder.taker,
            _dealOrder.dealAmount,
            totalFee,
            processRes
        );
    }

    function setController(address _controller) external {
        require(_controller != address(0), "zero address");
        require(msg.sender == address(controller), "the caller is not the controller");

        controller = IOpenmetaController(_controller);
    }

    function getOrderUserBalance(
        NftInfo memory _nftInfo, 
        MakerOrder memory _makerOrder, 
        address _taker,
        bool _originToken
    ) public view returns(uint256 nftBalance, uint256 amountBalance) {
        if (_nftInfo.tokenType == TokenType.TYPE_ERC721) {
            if (IERC721(_nftInfo.nftToken).ownerOf(_nftInfo.tokenId) == _makerOrder.maker) {
                nftBalance = 1;
            }
        }

        if (_nftInfo.tokenType == TokenType.TYPE_ERC1155) {
            nftBalance = IERC1155(_nftInfo.nftToken).balanceOf(_makerOrder.maker, _nftInfo.tokenId);
        }

        if (_originToken) {
            amountBalance = _taker.balance;
        } else {
            amountBalance = IERC20(_makerOrder.paymentToken).balanceOf(_taker);
        }
    }

    function _transferForTakeFee(
        NftInfo memory _nftInfo, 
        MakerOrder memory _makerOrder, 
        DealOrder memory _dealOrder,
        bool _originToken
    ) internal returns(uint256){
        /// Calculate the total fees for this order
        address feeTo = controller.feeTo();
        (uint256 amount, uint256 totalFee, uint256 txFee, uint256 authorFee) = controller.checkFeeAmount(
            _dealOrder.dealAmount,
            _makerOrder.authorProtocolFee
        );

        /// Complete transaction transfer based on payment token type
        if (_originToken) {
            require(msg.value >= _dealOrder.dealAmount, "insufficient value");

            TransferHelper.safeTransferETH(_makerOrder.maker, amount);

            if (txFee > 0) {
                TransferHelper.safeTransferETH(feeTo, txFee);
            }

            if (authorFee > 0) {
                TransferHelper.safeTransferETH(_dealOrder.author, authorFee);
            }
        } else {
            TransferHelper.safeTransferFrom(_makerOrder.paymentToken, msg.sender, _makerOrder.maker, amount);

            if (txFee > 0) {
                require(feeTo != address(0), "zero fee address");
                TransferHelper.safeTransferFrom(_makerOrder.paymentToken, msg.sender, feeTo, txFee);
            }

            if (authorFee > 0) {
                require(_dealOrder.author != address(0), "zero author address");
                TransferHelper.safeTransferFrom(_makerOrder.paymentToken, msg.sender, _dealOrder.author, authorFee);
            }
        }
        
        /// Check whether the order NFT Token has been minted. 
        /// If it has been minted, call the contract transfer method, 
        /// otherwise mint the NFT tokenid and send it to the taker
        if (_dealOrder.minted) {
            if (_nftInfo.tokenType == TokenType.TYPE_ERC721) {
                IERC721(_nftInfo.nftToken).safeTransferFrom(
                    _makerOrder.maker, 
                    _dealOrder.taker, 
                    _nftInfo.tokenId
                );
            }
            if (_nftInfo.tokenType == TokenType.TYPE_ERC1155) {
                IERC1155(_nftInfo.nftToken).safeTransferFrom(
                    _makerOrder.maker, 
                    _dealOrder.taker, 
                    _nftInfo.tokenId,
                    _makerOrder.quantity,
                    ""
                );
            }
        } else {
            controller.mint(
                _dealOrder.taker,
                _nftInfo.tokenId,
                1
            );
        }

        return totalFee;
    }
}