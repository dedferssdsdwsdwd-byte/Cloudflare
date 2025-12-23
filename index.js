import { connect } from 'cloudflare:sockets';

// ============================================================================
// 1. EMBEDDED LIBRARIES & CONSTANTS
// ============================================================================

/**
 * Embedded Lightweight QR Code Library (qrcode.js v1.0.0 adapted)
 * This allows local QR generation without external CDNs.
 */
const QR_LIB = `
var QRCode;
(function () {
    function QR8bitByte(data) {
        this.mode = QRMode.MODE_8BIT_BYTE;
        this.data = data;
        this.parsedData = [];
        for (var i = 0, l = this.data.length; i < l; i++) {
            var byte = [];
            var code = this.data.charCodeAt(i);
            if (code > 0x10000) {
                byte[0] = 0xF0 | ((code & 0x1C0000) >>> 18);
                byte[1] = 0x80 | ((code & 0x3F000) >>> 12);
                byte[2] = 0x80 | ((code & 0xFC0) >>> 6);
                byte[3] = 0x80 | (code & 0x3F);
            } else if (code > 0x800) {
                byte[0] = 0xE0 | ((code & 0xF000) >>> 12);
                byte[1] = 0x80 | ((code & 0xFC0) >>> 6);
                byte[2] = 0x80 | (code & 0x3F);
            } else if (code > 0x80) {
                byte[0] = 0xC0 | ((code & 0x7C0) >>> 6);
                byte[1] = 0x80 | (code & 0x3F);
            } else {
                byte[0] = code;
            }
            this.parsedData.push(byte);
        }
        this.parsedData = Array.prototype.concat.apply([], this.parsedData);
        if (this.parsedData.length != this.data.length) {
            this.parsedData.unshift(191);
            this.parsedData.unshift(187);
            this.parsedData.unshift(239);
        }
    }
    QR8bitByte.prototype = {
        getLength: function (buffer) {
            return this.parsedData.length;
        },
        write: function (buffer) {
            for (var i = 0, l = this.parsedData.length; i < l; i++) {
                buffer.put(this.parsedData[i], 8);
            }
        }
    };
    function QRCodeModel(typeNumber, errorCorrectLevel) {
        this.typeNumber = typeNumber;
        this.errorCorrectLevel = errorCorrectLevel;
        this.modules = null;
        this.moduleCount = 0;
        this.dataCache = null;
        this.dataList = [];
    }
    QRCodeModel.prototype = {
        addData: function (data) {
            var newData = new QR8bitByte(data);
            this.dataList.push(newData);
            this.dataCache = null;
        },
        isDark: function (row, col) {
            if (row < 0 || this.moduleCount <= row || col < 0 || this.moduleCount <= col) {
                throw new Error(row + "," + col);
            }
            return this.modules[row][col];
        },
        getModuleCount: function () {
            return this.moduleCount;
        },
        make: function () {
            this.makeImpl(false, this.getBestMaskPattern());
        },
        makeImpl: function (test, maskPattern) {
            this.moduleCount = this.typeNumber * 4 + 17;
            this.modules = new Array(this.moduleCount);
            for (var row = 0; row < this.moduleCount; row++) {
                this.modules[row] = new Array(this.moduleCount);
                for (var col = 0; col < this.moduleCount; col++) {
                    this.modules[row][col] = null;
                }
            }
            this.setupPositionProbePattern(0, 0);
            this.setupPositionProbePattern(this.moduleCount - 7, 0);
            this.setupPositionProbePattern(0, this.moduleCount - 7);
            this.setupPositionAdjustPattern();
            this.setupTimingPattern();
            this.setupTypeInfo(test, maskPattern);
            if (this.typeNumber >= 7) {
                this.setupTypeNumber(test);
            }
            if (this.dataCache == null) {
                this.dataCache = QRCodeModel.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);
            }
            this.mapData(this.dataCache, maskPattern);
        },
        setupPositionProbePattern: function (row, col) {
            for (var r = -1; r <= 7; r++) {
                if (row + r <= -1 || this.moduleCount <= row + r) continue;
                for (var c = -1; c <= 7; c++) {
                    if (col + c <= -1 || this.moduleCount <= col + c) continue;
                    if ((0 <= r && r <= 6 && (c == 0 || c == 6)) || (0 <= c && c <= 6 && (r == 0 || r == 6)) || (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
                        this.modules[row + r][col + c] = true;
                    } else {
                        this.modules[row + r][col + c] = false;
                    }
                }
            }
        },
        getBestMaskPattern: function () {
            var minPenalty = 0;
            var bestMaskPattern = 0;
            for (var i = 0; i < 8; i++) {
                this.makeImpl(true, i);
                var penalty = QRUtil.getLostPoint(this);
                if (i == 0 || minPenalty > penalty) {
                    minPenalty = penalty;
                    bestMaskPattern = i;
                }
            }
            return bestMaskPattern;
        },
        createMovieClip: function (target_mc, instance_name, depth) {
            var qr_mc = target_mc.createEmptyMovieClip(instance_name, depth);
            var cs = 1;
            this.make();
            for (var row = 0; row < this.modules.length; row++) {
                var y = row * cs;
                for (var col = 0; col < this.modules[row].length; col++) {
                    var x = col * cs;
                    var dark = this.modules[row][col];
                    if (dark) {
                        qr_mc.beginFill(0, 100);
                        qr_mc.moveTo(x, y);
                        qr_mc.lineTo(x + cs, y);
                        qr_mc.lineTo(x + cs, y + cs);
                        qr_mc.lineTo(x, y + cs);
                        qr_mc.endFill();
                    }
                }
            }
            return qr_mc;
        },
        setupTimingPattern: function () {
            for (var r = 8; r < this.moduleCount - 8; r++) {
                if (this.modules[r][6] != null) {
                    continue;
                }
                this.modules[r][6] = (r % 2 == 0);
            }
            for (var c = 8; c < this.moduleCount - 8; c++) {
                if (this.modules[6][c] != null) {
                    continue;
                }
                this.modules[6][c] = (c % 2 == 0);
            }
        },
        setupPositionAdjustPattern: function () {
            var pos = QRUtil.getPatternPosition(this.typeNumber);
            for (var i = 0; i < pos.length; i++) {
                for (var j = 0; j < pos.length; j++) {
                    var row = pos[i];
                    var col = pos[j];
                    if (this.modules[row][col] != null) {
                        continue;
                    }
                    for (var r = -2; r <= 2; r++) {
                        for (var c = -2; c <= 2; c++) {
                            if (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0)) {
                                this.modules[row + r][col + c] = true;
                            } else {
                                this.modules[row + r][col + c] = false;
                            }
                        }
                    }
                }
            }
        },
        setupTypeNumber: function (test) {
            var bits = QRUtil.getBCHTypeNumber(this.typeNumber);
            for (var i = 0; i < 18; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = mod;
                this.modules[Math.floor(i / 3) + this.moduleCount - 8 - 3][i % 3] = mod;
            }
        },
        setupTypeInfo: function (test, maskPattern) {
            var data = (this.errorCorrectLevel << 3) | maskPattern;
            var bits = QRUtil.getBCHTypeInfo(data);
            for (var i = 0; i < 15; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                if (i < 6) {
                    this.modules[i][8] = mod;
                } else if (i < 8) {
                    this.modules[i + 1][8] = mod;
                } else {
                    this.modules[this.moduleCount - 15 + i][8] = mod;
                }
                if (i < 8) {
                    this.modules[8][this.moduleCount - i - 1] = mod;
                } else if (i < 9) {
                    this.modules[8][15 - i - 1 + 1] = mod;
                } else {
                    this.modules[8][15 - i - 1] = mod;
                }
            }
            this.modules[this.moduleCount - 8][8] = (!test);
        },
        mapData: function (data, maskPattern) {
            var inc = -1;
            var row = this.moduleCount - 1;
            var bitIndex = 7;
            var byteIndex = 0;
            for (var col = this.moduleCount - 1; col > 0; col -= 2) {
                if (col == 6) col--;
                while (true) {
                    for (var c = 0; c < 2; c++) {
                        if (this.modules[row][col - c] == null) {
                            var dark = false;
                            if (byteIndex < data.length) {
                                dark = (((data[byteIndex] >>> bitIndex) & 1) == 1);
                            }
                            var mask = QRUtil.getMask(maskPattern, row, col - c);
                            if (mask) {
                                dark = !dark;
                            }
                            this.modules[row][col - c] = dark;
                            bitIndex--;
                            if (bitIndex == -1) {
                                byteIndex++;
                                bitIndex = 7;
                            }
                        }
                    }
                    row += inc;
                    if (row < 0 || this.moduleCount <= row) {
                        row -= inc;
                        inc = -inc;
                        break;
                    }
                }
            }
        }
    };
    QRCodeModel.createData = function (typeNumber, errorCorrectLevel, dataList) {
        var rsBlocks = RSBlock.getRSBlocks(typeNumber, errorCorrectLevel);
        var buffer = new QRBitBuffer();
        for (var i = 0; i < dataList.length; i++) {
            var data = dataList[i];
            buffer.put(data.mode, 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.mode, typeNumber));
            data.write(buffer);
        }
        var totalDataCount = 0;
        for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() > totalDataCount * 8) {
            throw new Error("code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")");
        }
        if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
            buffer.put(0, 4);
        }
        while (buffer.getLengthInBits() % 8 != 0) {
            buffer.putBit(false);
        }
        while (true) {
            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(236, 8);
            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(17, 8);
        }
        return QRCodeModel.createBytes(buffer, rsBlocks);
    };
    QRCodeModel.createBytes = function (buffer, rsBlocks) {
        var offset = 0;
        var maxDcCount = 0;
        var maxEcCount = 0;
        var dcdata = new Array(rsBlocks.length);
        var ecdata = new Array(rsBlocks.length);
        for (var r = 0; r < rsBlocks.length; r++) {
            var dcCount = rsBlocks[r].dataCount;
            var ecCount = rsBlocks[r].totalCount - dcCount;
            maxDcCount = Math.max(maxDcCount, dcCount);
            maxEcCount = Math.max(maxEcCount, ecCount);
            dcdata[r] = new Array(dcCount);
            for (var i = 0; i < dcCount; i++) {
                dcdata[r][i] = 0xff & buffer.buffer[i + offset];
            }
            offset += dcCount;
            var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
            var rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1);
            var modPoly = rawPoly.mod(rsPoly);
            ecdata[r] = new Array(rsPoly.getLength() - 1);
            for (var i = 0; i < ecdata[r].length; i++) {
                var modIndex = i + modPoly.getLength() - ecdata[r].length;
                if (modIndex >= 0) {
                    ecdata[r][i] = modPoly.get(modIndex);
                } else {
                    ecdata[r][i] = 0;
                }
            }
        }
        var totalCodeCount = 0;
        for (var i = 0; i < rsBlocks.length; i++) {
            totalCodeCount += rsBlocks[i].totalCount;
        }
        var data = new Array(totalCodeCount);
        var index = 0;
        for (var i = 0; i < maxDcCount; i++) {
            for (var r = 0; r < rsBlocks.length; r++) {
                if (i < dcdata[r].length) {
                    data[index++] = dcdata[r][i];
                }
            }
        }
        for (var i = 0; i < maxEcCount; i++) {
            for (var r = 0; r < rsBlocks.length; r++) {
                if (i < ecdata[r].length) {
                    data[index++] = ecdata[r][i];
                }
            }
        }
        return data;
    };
    var QRMode = {
        MODE_NUMBER: 1 << 0,
        MODE_ALPHA_NUM: 1 << 1,
        MODE_8BIT_BYTE: 1 << 2,
        MODE_KANJI: 1 << 3
    };
    var QRErrorCorrectLevel = {
        L: 1,
        M: 0,
        Q: 3,
        H: 2
    };
    var QRMaskPattern = {
        PATTERN000: 0,
        PATTERN001: 1,
        PATTERN010: 2,
        PATTERN011: 3,
        PATTERN100: 4,
        PATTERN101: 5,
        PATTERN110: 6,
        PATTERN111: 7
    };
    var QRUtil = {
        PATTERN_POSITION_TABLE: [
            [],
            [6, 18],
            [6, 22],
            [6, 26],
            [6, 30],
            [6, 34],
            [6, 22, 38],
            [6, 24, 42],
            [6, 26, 46],
            [6, 28, 50],
            [6, 30, 54],
            [6, 32, 58],
            [6, 34, 62],
            [6, 26, 46, 66],
            [6, 26, 48, 70],
            [6, 26, 50, 74],
            [6, 30, 54, 78],
            [6, 30, 56, 82],
            [6, 30, 58, 86],
            [6, 34, 62, 90],
            [6, 28, 50, 72, 94],
            [6, 26, 50, 74, 98],
            [6, 30, 54, 78, 102],
            [6, 28, 54, 80, 106],
            [6, 32, 58, 84, 110],
            [6, 30, 58, 86, 114],
            [6, 34, 62, 90, 118],
            [6, 26, 50, 74, 98, 122],
            [6, 30, 54, 78, 102, 126],
            [6, 26, 52, 78, 104, 130],
            [6, 30, 56, 82, 108, 134],
            [6, 34, 60, 86, 112, 138],
            [6, 30, 58, 86, 114, 142],
            [6, 34, 62, 90, 118, 146],
            [6, 30, 54, 78, 102, 126, 150],
            [6, 24, 50, 76, 102, 128, 154],
            [6, 28, 54, 80, 106, 132, 158],
            [6, 32, 58, 84, 110, 136, 162],
            [6, 26, 54, 82, 110, 138, 166],
            [6, 30, 58, 86, 114, 142, 170]
        ],
        G15: (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0),
        G18: (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0),
        G15_MASK: (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1),
        getBCHTypeInfo: function (data) {
            var d = data << 10;
            while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) {
                d ^= (QRUtil.G15 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15)));
            }
            return ((data << 10) | d) ^ QRUtil.G15_MASK;
        },
        getBCHTypeNumber: function (data) {
            var d = data << 12;
            while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) >= 0) {
                d ^= (QRUtil.G18 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18)));
            }
            return (data << 12) | d;
        },
        getBCHDigit: function (data) {
            var digit = 0;
            while (data != 0) {
                digit++;
                data >>>= 1;
            }
            return digit;
        },
        getPatternPosition: function (typeNumber) {
            return QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1];
        },
        getMask: function (maskPattern, i, j) {
            switch (maskPattern) {
                case QRMaskPattern.PATTERN000:
                    return (i + j) % 2 == 0;
                case QRMaskPattern.PATTERN001:
                    return i % 2 == 0;
                case QRMaskPattern.PATTERN010:
                    return j % 3 == 0;
                case QRMaskPattern.PATTERN011:
                    return (i + j) % 3 == 0;
                case QRMaskPattern.PATTERN100:
                    return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
                case QRMaskPattern.PATTERN101:
                    return (i * j) % 2 + (i * j) % 3 == 0;
                case QRMaskPattern.PATTERN110:
                    return ((i * j) % 2 + (i * j) % 3) % 2 == 0;
                case QRMaskPattern.PATTERN111:
                    return ((i * j) % 3 + (i + j) % 2) % 2 == 0;
                default:
                    throw new Error("bad maskPattern:" + maskPattern);
            }
        },
        getErrorCorrectPolynomial: function (errorCorrectLength) {
            var a = new QRPolynomial([1], 0);
            for (var i = 0; i < errorCorrectLength; i++) {
                a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0));
            }
            return a;
        },
        getLengthInBits: function (mode, type) {
            if (1 <= type && type < 10) {
                switch (mode) {
                    case QRMode.MODE_NUMBER: return 10;
                    case QRMode.MODE_ALPHA_NUM: return 9;
                    case QRMode.MODE_8BIT_BYTE: return 8;
                    case QRMode.MODE_KANJI: return 8;
                    default: throw new Error("mode:" + mode);
                }
            } else if (type < 27) {
                switch (mode) {
                    case QRMode.MODE_NUMBER: return 12;
                    case QRMode.MODE_ALPHA_NUM: return 11;
                    case QRMode.MODE_8BIT_BYTE: return 16;
                    case QRMode.MODE_KANJI: return 10;
                    default: throw new Error("mode:" + mode);
                }
            } else if (type < 41) {
                switch (mode) {
                    case QRMode.MODE_NUMBER: return 14;
                    case QRMode.MODE_ALPHA_NUM: return 13;
                    case QRMode.MODE_8BIT_BYTE: return 16;
                    case QRMode.MODE_KANJI: return 12;
                    default: throw new Error("mode:" + mode);
                }
            } else {
                throw new Error("type:" + type);
            }
        },
        getLostPoint: function (qrCode) {
            var moduleCount = qrCode.getModuleCount();
            var lostPoint = 0;
            for (var row = 0; row < moduleCount; row++) {
                for (var col = 0; col < moduleCount; col++) {
                    var sameCount = 0;
                    var dark = qrCode.isDark(row, col);
                    for (var r = -1; r <= 1; r++) {
                        if (row + r < 0 || moduleCount <= row + r) {
                            continue;
                        }
                        for (var c = -1; c <= 1; c++) {
                            if (col + c < 0 || moduleCount <= col + c) {
                                continue;
                            }
                            if (r == 0 && c == 0) {
                                continue;
                            }
                            if (dark == qrCode.isDark(row + r, col + c)) {
                                sameCount++;
                            }
                        }
                    }
                    if (sameCount > 5) {
                        lostPoint += (3 + sameCount - 5);
                    }
                }
            }
            for (var row = 0; row < moduleCount - 1; row++) {
                for (var col = 0; col < moduleCount - 1; col++) {
                    var count = 0;
                    if (qrCode.isDark(row, col)) count++;
                    if (qrCode.isDark(row + 1, col)) count++;
                    if (qrCode.isDark(row, col + 1)) count++;
                    if (qrCode.isDark(row + 1, col + 1)) count++;
                    if (count == 0 || count == 4) {
                        lostPoint += 3;
                    }
                }
            }
            for (var row = 0; row < moduleCount; row++) {
                for (var col = 0; col < moduleCount - 6; col++) {
                    if (qrCode.isDark(row, col) && !qrCode.isDark(row, col + 1) && qrCode.isDark(row, col + 2) && qrCode.isDark(row, col + 3) && qrCode.isDark(row, col + 4) && !qrCode.isDark(row, col + 5) && qrCode.isDark(row, col + 6)) {
                        lostPoint += 40;
                    }
                }
            }
            for (var col = 0; col < moduleCount; col++) {
                for (var row = 0; row < moduleCount - 6; row++) {
                    if (qrCode.isDark(row, col) && !qrCode.isDark(row + 1, col) && qrCode.isDark(row + 2, col) && qrCode.isDark(row + 3, col) && qrCode.isDark(row + 4, col) && !qrCode.isDark(row + 5, col) && qrCode.isDark(row + 6, col)) {
                        lostPoint += 40;
                    }
                }
            }
            var darkCount = 0;
            for (var col = 0; col < moduleCount; col++) {
                for (var row = 0; row < moduleCount; row++) {
                    if (qrCode.isDark(row, col)) {
                        darkCount++;
                    }
                }
            }
            var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
            lostPoint += ratio * 10;
            return lostPoint;
        }
    };
    var QRMath = {
        glog: function (n) {
            if (n < 1) {
                throw new Error("glog(" + n + ")");
            }
            return QRMath.LOG_TABLE[n];
        },
        gexp: function (n) {
            while (n < 0) {
                n += 255;
            }
            while (n >= 256) {
                n -= 255;
            }
            return QRMath.EXP_TABLE[n];
        },
        EXP_TABLE: new Array(256),
        LOG_TABLE: new Array(256)
    };
    for (var i = 0; i < 8; i++) {
        QRMath.EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i++) {
        QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i++) {
        QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;
    }
    function QRPolynomial(num, shift) {
        if (num.length == undefined) {
            throw new Error(num.length + "/" + shift);
        }
        var offset = 0;
        while (offset < num.length && num[offset] == 0) {
            offset++;
        }
        this.num = new Array(num.length - offset + shift);
        for (var i = 0; i < num.length - offset; i++) {
            this.num[i] = num[i + offset];
        }
    }
    QRPolynomial.prototype = {
        get: function (index) {
            return this.num[index];
        },
        getLength: function () {
            return this.num.length;
        },
        multiply: function (e) {
            var num = new Array(this.getLength() + e.getLength() - 1);
            for (var i = 0; i < this.getLength(); i++) {
                for (var j = 0; j < e.getLength(); j++) {
                    num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j)));
                }
            }
            return new QRPolynomial(num, 0);
        },
        mod: function (e) {
            if (this.getLength() - e.getLength() < 0) {
                return this;
            }
            var ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0));
            var num = new Array(this.getLength());
            for (vari = 0; i < this.getLength(); i++) {
                num[i] = this.get(i);
            }
            for (var i = 0; i < e.getLength(); i++) {
                num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio);
            }
            return new QRPolynomial(num, 0).mod(e);
        }
    };
    function RSBlock(totalCount, dataCount) {
        this.totalCount = totalCount;
        this.dataCount = dataCount;
    }
    RSBlock.RS_BLOCK_TABLE = [
        [1, 26, 19],
        [1, 26, 16],
        [1, 26, 13],
        [1, 26, 9],
        [1, 44, 34],
        [1, 44, 28],
        [1, 44, 22],
        [1, 44, 16],
        [1, 70, 55],
        [1, 70, 44],
        [2, 35, 17],
        [2, 35, 13],
        [1, 100, 80],
        [2, 50, 32],
        [2, 50, 24],
        [4, 25, 9],
        [1, 134, 108],
        [2, 67, 43],
        [2, 33, 15, 2, 34, 16],
        [2, 33, 11, 2, 34, 12],
        [2, 86, 68],
        [4, 43, 27],
        [4, 43, 19],
        [4, 43, 15],
        [2, 98, 78],
        [4, 49, 31],
        [2, 32, 14, 4, 33, 15],
        [4, 39, 13, 1, 40, 14],
        [2, 121, 97],
        [2, 60, 38, 2, 61, 39],
        [4, 40, 18, 2, 41, 19],
        [4, 40, 14, 2, 41, 15],
        [2, 146, 116],
        [3, 58, 36, 2, 59, 37],
        [4, 36, 16, 4, 37, 17],
        [4, 36, 12, 4, 37, 13],
        [2, 86, 68, 2, 87, 69],
        [4, 69, 43, 1, 70, 44],
        [6, 43, 19, 2, 44, 20],
        [6, 43, 15, 2, 44, 16],
        [4, 101, 81],
        [1, 80, 50, 4, 81, 51],
        [4, 50, 22, 4, 51, 23],
        [3, 36, 12, 8, 37, 13],
        [2, 116, 92, 2, 117, 93],
        [6, 58, 36, 2, 59, 37],
        [4, 46, 20, 6, 47, 21],
        [7, 42, 14, 4, 43, 15],
        [4, 133, 107],
        [8, 59, 37, 1, 60, 38],
        [8, 44, 20, 4, 45, 21],
        [12, 33, 11, 4, 34, 12],
        [3, 145, 115, 1, 146, 116],
        [4, 64, 40, 5, 65, 41],
        [11, 36, 16, 5, 37, 17],
        [11, 36, 12, 5, 37, 13],
        [5, 109, 87, 1, 110, 88],
        [5, 65, 41, 5, 66, 42],
        [5, 54, 24, 7, 55, 25],
        [11, 36, 12],
        [5, 122, 98, 1, 123, 99],
        [7, 73, 45, 3, 74, 46],
        [15, 43, 19, 2, 44, 20],
        [3, 45, 15, 13, 46, 16],
        [1, 135, 107, 5, 136, 108],
        [10, 74, 46, 1, 75, 47],
        [1, 50, 22, 15, 51, 23],
        [2, 42, 14, 17, 43, 15],
        [5, 150, 120, 1, 151, 121],
        [9, 69, 43, 4, 70, 44],
        [17, 50, 22, 1, 51, 23],
        [2, 42, 14, 19, 43, 15],
        [3, 141, 113, 4, 142, 114],
        [3, 70, 44, 11, 71, 45],
        [17, 47, 21, 4, 48, 22],
        [9, 39, 13, 16, 40, 14],
        [3, 135, 107, 5, 136, 108],
        [3, 67, 41, 13, 68, 42],
        [15, 54, 24, 5, 55, 25],
        [15, 43, 15, 10, 44, 16],
        [4, 144, 116, 4, 145, 117],
        [17, 68, 42],
        [17, 50, 22, 6, 51, 23],
        [19, 46, 16, 6, 47, 17],
        [2, 139, 111, 7, 140, 112],
        [17, 74, 46],
        [7, 54, 24, 16, 55, 25],
        [34, 37, 13],
        [4, 151, 121, 5, 152, 122],
        [4, 75, 47, 14, 76, 48],
        [11, 54, 24, 14, 55, 25],
        [16, 45, 15, 14, 46, 16],
        [6, 147, 117, 4, 148, 118],
        [6, 73, 45, 14, 74, 46],
        [11, 54, 24, 16, 55, 25],
        [30, 46, 16, 2, 47, 17],
        [8, 132, 106, 4, 133, 107],
        [8, 75, 47, 13, 76, 48],
        [7, 54, 24, 22, 55, 25],
        [22, 45, 15, 13, 46, 16],
        [10, 142, 114, 2, 143, 115],
        [19, 74, 46, 4, 75, 47],
        [28, 50, 22, 6, 51, 23],
        [33, 46, 16, 4, 47, 17],
        [8, 152, 122, 4, 153, 123],
        [22, 73, 45, 3, 74, 46],
        [8, 53, 23, 26, 54, 24],
        [12, 45, 15, 28, 46, 16],
        [3, 147, 117, 10, 148, 118],
        [3, 73, 45, 23, 74, 46],
        [4, 54, 24, 31, 55, 25],
        [11, 45, 15, 31, 46, 16],
        [7, 146, 116, 7, 147, 117],
        [21, 73, 45, 7, 74, 46],
        [1, 53, 23, 37, 54, 24],
        [19, 45, 15, 26, 46, 16],
        [5, 145, 115, 10, 146, 116],
        [19, 75, 47, 10, 76, 48],
        [15, 54, 24, 25, 55, 25],
        [23, 45, 15, 25, 46, 16],
        [13, 145, 115, 3, 146, 116],
        [2, 74, 46, 29, 75, 47],
        [42, 54, 24, 1, 55, 25],
        [23, 45, 15, 28, 46, 16],
        [17, 145, 115],
        [10, 74, 46, 23, 75, 47],
        [10, 54, 24, 35, 55, 25],
        [19, 45, 15, 35, 46, 16],
        [17, 145, 115, 1, 146, 116],
        [14, 74, 46, 21, 75, 47],
        [29, 54, 24, 19, 55, 25],
        [11, 45, 15, 46, 46, 16],
        [13, 145, 115, 6, 146, 116],
        [14, 74, 46, 23, 75, 47],
        [44, 54, 24, 7, 55, 25],
        [59, 46, 16, 1, 47, 17],
        [12, 151, 121, 7, 152, 122],
        [12, 75, 47, 26, 76, 48],
        [39, 54, 24, 14, 55, 25],
        [22, 45, 15, 41, 46, 16],
        [6, 151, 121, 14, 152, 122],
        [6, 75, 47, 34, 76, 48],
        [46, 54, 24, 10, 55, 25],
        [2, 45, 15, 64, 46, 16],
        [17, 152, 122, 4, 153, 123],
        [29, 74, 46, 14, 75, 47],
        [49, 54, 24, 10, 55, 25],
        [24, 45, 15, 46, 46, 16],
        [4, 152, 122, 18, 153, 123],
        [13, 74, 46, 32, 75, 47],
        [48, 54, 24, 14, 55, 25],
        [42, 45, 15, 32, 46, 16],
        [20, 147, 117, 4, 148, 118],
        [40, 75, 47, 7, 76, 48],
        [43, 54, 24, 22, 55, 25],
        [10, 45, 15, 67, 46, 16],
        [19, 148, 118, 6, 149, 119],
        [18, 75, 47, 31, 76, 48],
        [34, 54, 24, 34, 55, 25],
        [20, 45, 15, 61, 46, 16]
    ];
    RSBlock.getRSBlocks = function (typeNumber, errorCorrectLevel) {
        var rsBlock = RSBlock.getRsBlockTable(typeNumber, errorCorrectLevel);
        if (rsBlock == undefined) {
            throw new Error("bad rs block @ typeNumber:" + typeNumber + "/errorCorrectLevel:" + errorCorrectLevel);
        }
        var length = rsBlock.length / 3;
        var list = [];
        for (var i = 0; i < length; i++) {
            var count = rsBlock[i * 3 + 0];
            var totalCount = rsBlock[i * 3 + 1];
            var dataCount = rsBlock[i * 3 + 2];
            for (var j = 0; j < count; j++) {
                list.push(new RSBlock(totalCount, dataCount));
            }
        }
        return list;
    };
    RSBlock.getRsBlockTable = function (typeNumber, errorCorrectLevel) {
        switch (errorCorrectLevel) {
            case QRErrorCorrectLevel.L: return RSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
            case QRErrorCorrectLevel.M: return RSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
            case QRErrorCorrectLevel.Q: return RSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
            case QRErrorCorrectLevel.H: return RSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
            default: return undefined;
        }
    };
    function QRBitBuffer() {
        this.buffer = [];
        this.length = 0;
    }
    QRBitBuffer.prototype = {
        get: function (index) {
            var bufIndex = Math.floor(index / 8);
            return ((this.buffer[bufIndex] >>> (7 - index % 8)) & 1) == 1;
        },
        put: function (num, length) {
            for (var i = 0; i < length; i++) {
                this.putBit(((num >>> (length - i - 1)) & 1) == 1);
            }
        },
        getLengthInBits: function () {
            return this.length;
        },
        putBit: function (bit) {
            var bufIndex = Math.floor(this.length / 8);
            if (this.buffer.length <= bufIndex) {
                this.buffer.push(0);
            }
            if (bit) {
                this.buffer[bufIndex] |= (0x80 >>> (this.length % 8));
            }
            this.length++;
        }
    };
    window.QRCode = QRCodeModel;
})();
`;

// ============================================================================
// 2. CONFIGURATION & CONSTANTS
// ============================================================================

/**
 * Configuration object merged from environment and default values.
 * Includes Scamalytics API, Proxy IP, and Worker sub-domain logic.
 */
const Config = {
    uuid: '99849511-9257-4180-9280-492759247599', // Default admin UUID
    proxyIP: 'cdn.xn--b6gac.eu.org',
    remoteDNS: 'https://1.1.1.1/dns-query',
    sub: 'worker-vless.kv.k00.eu.org',
    PROV: 'KV',
    API: 'https://scamalytics.com/ip/', // Anti-fraud check integration
    
    // DB Config
    DB: null, // Will be injected from env
};

/**
 * Helper to safely encode strings to Base64 (supporting UTF-8)
 * FIX: 'Info Scan' issue where some characters caused failed decoding.
 */
function safeBase64(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function(match, p1) {
            return String.fromCharCode('0x' + p1);
        }));
}

// ============================================================================
// 3. DATABASE UTILITIES (D1)
// ============================================================================

/**
 * Initialize the D1 database if it doesn't exist.
 * Creates tables for users and usage tracking.
 */
async function initializeDatabase(db) {
    try {
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                name TEXT,
                email TEXT,
                telegram_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL,
                upload INTEGER DEFAULT 0,
                download INTEGER DEFAULT 0,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(uuid) REFERENCES users(uuid)
            );
        `);
        // Ensure admin UUID exists
        const adminCheck = await db.prepare("SELECT uuid FROM users WHERE uuid = ?").bind(Config.uuid).first();
        if (!adminCheck) {
            await db.prepare("INSERT INTO users (uuid, name) VALUES (?, ?)").bind(Config.uuid, 'Admin').run();
        }
    } catch (e) {
        console.error("DB Init Error:", e);
    }
}

async function verifyUser(db, uuid) {
    if (!uuid) return false;
    // Allow static admin UUID even if DB fails
    if (uuid === Config.uuid) return true;
    
    try {
        const user = await db.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        return !!user;
    } catch (e) {
        // Fallback for non-D1 environments or critical errors
        return uuid === Config.uuid;
    }
}

async function addVLESSKey(db, uuid, name) {
    try {
        await db.prepare("INSERT INTO users (uuid, name) VALUES (?, ?)").bind(uuid, name).run();
        return true;
    } catch (e) {
        return false;
    }
}

async function deleteVLESSKey(db, uuid) {
    if (uuid === Config.uuid) return false; // Cannot delete main admin
    try {
        await db.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
        return true;
    } catch (e) {
        return false;
    }
}

async function getVLESSKeys(db) {
    try {
        const result = await db.prepare("SELECT users.uuid, users.name, usage.upload, usage.download, usage.last_active FROM users LEFT JOIN usage ON users.uuid = usage.uuid").all();
        return result.results || [];
    } catch (e) {
        return [{ uuid: Config.uuid, name: 'Admin (Static)', upload: 0, download: 0 }];
    }
}

async function updateUsage(db, uuid, up, down) {
    if (!db || !uuid) return;
    try {
        // Upsert usage
        const exists = await db.prepare("SELECT id FROM usage WHERE uuid = ?").bind(uuid).first();
        if (exists) {
            await db.prepare("UPDATE usage SET upload = upload + ?, download = download + ?, last_active = CURRENT_TIMESTAMP WHERE uuid = ?")
                .bind(up, down, uuid).run();
        } else {
            await db.prepare("INSERT INTO usage (uuid, upload, download) VALUES (?, ?, ?)")
                .bind(uuid, up, down).run();
        }
    } catch (e) {
        console.error("Usage Update Error:", e);
    }
}

// ============================================================================
// 4. HTML & CSS TEMPLATES (Glassmorphism)
// ============================================================================

const ADMIN_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum VLESS Panel</title>
    <style>
        :root {
            --glass-bg: rgba(255, 255, 255, 0.1);
            --glass-border: rgba(255, 255, 255, 0.2);
            --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            --text-color: #ffffff;
            --accent-color: #00f2ff;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(45deg, #1a1a2e, #16213e, #0f3460);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            color: var(--text-color);
            min-height: 100vh;
        }
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .glass-panel {
            background: var(--glass-bg);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid var(--glass-border);
            box-shadow: var(--glass-shadow);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2, h3 {
            color: var(--accent-color);
            text-shadow: 0 0 10px rgba(0, 242, 255, 0.5);
        }
        button {
            background: rgba(0, 242, 255, 0.2);
            border: 1px solid var(--accent-color);
            color: var(--accent-color);
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: bold;
        }
        button:hover {
            background: var(--accent-color);
            color: #000;
            box-shadow: 0 0 15px var(--accent-color);
        }
        input {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--glass-border);
            color: white;
            padding: 10px;
            border-radius: 8px;
            margin-right: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--glass-border);
        }
        th {
            color: var(--accent-color);
        }
        .qr-container {
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }
        .hidden { display: none; }
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 255, 128, 0.2);
            border: 1px solid #00ff80;
            color: #fff;
            padding: 15px;
            border-radius: 8px;
            display: none;
            backdrop-filter: blur(4px);
        }
        /* Mobile Responsive */
        @media (max-width: 768px) {
            .container { padding: 10px; }
            th, td { font-size: 14px; padding: 8px; }
            .action-btn { display: block; width: 100%; margin: 5px 0; }
        }
    </style>
</head>
<body>
`;
    <div class="container">
        <div class="glass-panel" style="display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 15px;">
                <div style="font-size: 24px;">🔮</div>
                <div>
                    <h2 style="margin: 0;">Quantum VLESS</h2>
                    <small style="opacity: 0.7;">Cloudflare Edge Node</small>
                </div>
            </div>
            <div id="stats-bar" style="display: flex; gap: 15px; align-items: center;">
                <span id="sys-status" style="color: #00ff80; border: 1px solid #00ff80; padding: 2px 8px; border-radius: 4px; font-size: 12px;">Operational</span>
            </div>
        </div>

        <div class="glass-panel">
            <h3>User Management</h3>
            <div style="display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;">
                <input type="text" id="newUserInfo" placeholder="User Name / ID" style="flex: 1; min-width: 200px;">
                <button onclick="addUser()">✨ Create User</button>
            </div>
            
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Name</th>
                            <th>UUID</th>
                            <th>Data (Up/Down)</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="userTableBody">
                        <tr><td colspan="5" style="text-align: center;">Loading Quantum Data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- QR Modal -->
        <div id="qrModal" class="glass-panel" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 1000; text-align: center; border: 1px solid var(--accent-color); background: rgba(0,0,0,0.9);">
            <h3 style="margin-top: 0;">Connection QR</h3>
            <div id="qrcode" style="background: white; padding: 10px; border-radius: 4px; margin: 0 auto; width: 200px;"></div>
            <br>
            <textarea id="qrText" style="width: 100%; height: 60px; font-size: 10px; color: #aaa; background: #111; border: 1px solid #333;" readonly></textarea>
            <br><br>
            <div style="display: flex; gap: 10px; justify-content: center;">
                <button onclick="copyLink()">Copy Link</button>
                <button onclick="closeQR()" style="border-color: #ff4444; color: #ff4444;">Close</button>
            </div>
        </div>
        
        <div id="toast" class="toast">Action Successful</div>
    </div>

    <script>
        // Inject Embedded QR Library Code
        ${QR_LIB}

        const API_BASE = window.location.pathname.replace('/panel', '/api');
        
        function showToast(msg) {
            const t = document.getElementById('toast');
            t.innerText = msg;
            t.style.display = 'block';
            setTimeout(() => t.style.display = 'none', 3000);
        }

        async function fetchUsers() {
            try {
                // If API_KEY is required in headers, add here. 
                // For this VLESS panel, we usually rely on the UUID path or a session, 
                // but for simplicity, we assume the Admin Panel is protected by the path param.
                const urlParams = new URLSearchParams(window.location.search);
                const authKey = urlParams.get('key');
                
                const res = await fetch(API_BASE + '/users' + (authKey ? '?key=' + authKey : ''));
                if(!res.ok) throw new Error('Auth Failed');
                
                const users = await res.json();
                renderTable(users);
            } catch (e) {
                console.error(e);
                document.getElementById('userTableBody').innerHTML = '<tr><td colspan="5" style="color: #ff4444;">Failed to load data. Auth Key required?</td></tr>';
            }
        }

        function renderTable(users) {
            const tbody = document.getElementById('userTableBody');
            tbody.innerHTML = '';
            
            users.forEach(u => {
                const tr = document.createElement('tr');
                // Check active status (within last 5 mins)
                const lastActive = u.last_active ? new Date(u.last_active).getTime() : 0;
                const isOnline = (Date.now() - lastActive) < 300000 && u.download > 0;
                
                tr.innerHTML = \`
                    <td><span style="color: \${isOnline ? '#00ff80' : '#555'}">●</span></td>
                    <td>\${u.name || 'Unknown'}</td>
                    <td style="font-family: monospace; font-size: 12px; opacity: 0.8;">\${u.uuid}</td>
                    <td>\${formatBytes(u.upload)} / \${formatBytes(u.download)}</td>
                    <td>
                        <button onclick="showQR('\${u.uuid}', '\${u.name}')" style="padding: 5px 10px;">Connect</button>
                        \${u.name !== 'Admin' ? \`<button onclick="deleteUser('\${u.uuid}')" style="background: rgba(255, 68, 68, 0.1); border-color: #ff4444; color: #ff4444; padding: 5px 10px;">Del</button>\` : ''}
                    </td>
                \`;
                tbody.appendChild(tr);
            });
        }

        async function addUser() {
            const name = document.getElementById('newUserInfo').value;
            if (!name) return alert('Enter a name');
            
            const urlParams = new URLSearchParams(window.location.search);
            const authKey = urlParams.get('key');

            await fetch(API_BASE + '/user' + (authKey ? '?key=' + authKey : ''), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name })
            });
            document.getElementById('newUserInfo').value = '';
            showToast('User Created');
            fetchUsers();
        }

        async function deleteUser(uuid) {
            if (!confirm('Confirm deletion?')) return;
            const urlParams = new URLSearchParams(window.location.search);
            const authKey = urlParams.get('key');
            
            await fetch(API_BASE + '/user?uuid=' + uuid + (authKey ? '&key=' + authKey : ''), { method: 'DELETE' });
            showToast('User Deleted');
            fetchUsers();
        }

        function formatBytes(bytes, decimals = 2) {
            if (!+bytes) return '0 B';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return \`\${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} \${sizes[i]}\`;
        }

        function showQR(uuid, name) {
            const host = window.location.hostname;
            // Robust VLESS Link Construction
            const link = \`vless://\${uuid}@\${host}:443?encryption=none&security=tls&sni=\${host}&fp=random&type=ws&host=\${host}&path=%2F%3Fed%3D2048#\${encodeURIComponent(name || 'QuantumNode')}\`;
            
            const qrDiv = document.getElementById('qrcode');
            qrDiv.innerHTML = '';
            // Generate QR Locally using the embedded library
            new QRCode(qrDiv, {
                text: link,
                width: 180,
                height: 180,
                colorDark : "#000000",
                colorLight : "#ffffff",
                correctLevel : QRCode.CorrectLevel.M
            });
            
            document.getElementById('qrText').value = link;
            document.getElementById('qrModal').style.display = 'block';
        }

        function closeQR() {
            document.getElementById('qrModal').style.display = 'none';
        }

        function copyLink() {
            const copyText = document.getElementById("qrText");
            copyText.select();
            copyText.setSelectionRange(0, 99999); 
            navigator.clipboard.writeText(copyText.value);
            showToast("Link Copied!");
        }

        // Initial Load
        fetchUsers();
    </script>
</body>
</html>
`;

// ============================================================================
// 5. MAIN WORKER ENTRY POINT
// ============================================================================

export default {
    async fetch(request, env, ctx) {
        // 1. Merge Environment Variables into Config
        const uuid = env.UUID || Config.uuid;
        const proxyIP = env.PROXYIP || Config.proxyIP;
        const db = env.DB;
        
        // Update Global Config
        Config.uuid = uuid;
        Config.proxyIP = proxyIP;
        Config.DB = db;

        // 2. Initialize Database (D1)
        if (Config.DB) {
            ctx.waitUntil(initializeDatabase(Config.DB));
        }

        const url = new URL(request.url);

        // 3. Router
        
        // A. Admin Panel & API
        if (url.pathname.startsWith('/panel') || url.pathname.startsWith('/api')) {
            return handleAdminRequest(request, url, env);
        }

        // B. VLESS WebSocket Handler
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader === 'websocket') {
            return await vlessOverWSHandler(request);
        }

        // C. Default Fallback (Decoy Page or Simple Info)
        const vlessLink = `vless://${Config.uuid}@${url.hostname}:443?encryption=none&security=tls&sni=${url.hostname}&fp=random&type=ws&host=${url.hostname}&path=%2F%3Fed%3D2048#${url.hostname}`;
        
        return new Response(`
        <html>
        <head><title>Quantum VLESS</title></head>
        <body style="background: #0f0f0f; color: #333; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh;">
            <div style="text-align: center;">
                <h1>Quantum Edge Node</h1>
                <p>Status: Active</p>
                <p>Protocol: VLESS + WS + TLS</p>
            </div>
        </body>
        </html>`, { 
            status: 200, 
            headers: { 'Content-Type': 'text/html' } 
        });
    }
};
/**
 * Handles Admin Panel and API requests.
 * Routes: /panel, /api/users, /api/user
 */
async function handleAdminRequest(request, url, env) {
    const key = url.searchParams.get('key');
    
    // Simple authentication: The key parameter must match the Admin UUID
    // In a production env, you might want headers, but query param is standard for these panels.
    if (key !== Config.uuid) {
        return new Response('Unauthorized Access. Please provide the correct Admin UUID key.', { status: 401 });
    }

    // Serve HTML Panel
    if (url.pathname === '/panel') {
        return new Response(ADMIN_HTML, {
            headers: { 'Content-Type': 'text/html' }
        });
    }

    // API: Get Users
    if (url.pathname === '/api/users' && request.method === 'GET') {
        if (!Config.DB) {
             // Fallback for non-D1 environments
             return new Response(JSON.stringify([{ 
                 uuid: Config.uuid, 
                 name: 'Admin (Static)', 
                 upload: 0, 
                 download: 0, 
                 last_active: new Date().toISOString() 
             }]), { headers: { 'Content-Type': 'application/json' }});
        }
        const users = await getVLESSKeys(Config.DB);
        return new Response(JSON.stringify(users), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // API: Create User
    if (url.pathname === '/api/user' && request.method === 'POST') {
        if (!Config.DB) return new Response('Database not configured', { status: 500 });
        const body = await request.json();
        // Generate a new UUID for the user
        const newUuid = crypto.randomUUID();
        await addVLESSKey(Config.DB, newUuid, body.name);
        return new Response(JSON.stringify({ uuid: newUuid, status: 'ok' }), { headers: { 'Content-Type': 'application/json' }});
    }

    // API: Delete User
    if (url.pathname === '/api/user' && request.method === 'DELETE') {
        if (!Config.DB) return new Response('Database not configured', { status: 500 });
        const targetUuid = url.searchParams.get('uuid');
        await deleteVLESSKey(Config.DB, targetUuid);
        return new Response(JSON.stringify({ status: 'ok' }), { headers: { 'Content-Type': 'application/json' }});
    }

    return new Response('Not Found', { status: 404 });
}

/**
 * Handles the VLESS WebSocket upgrade.
 * Establishes the WebSocket pair and starts the VLESS protocol processor.
 */
async function vlessOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    server.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => {
        // console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    // Convert the WebSocket into a readable stream for processing
    const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader, log);

    let remoteSocketWrapper = {
        value: null,
    };

    // Begin processing the VLESS stream
    // We do not await this here; it runs in the background handling the connection
    handleVLESSClient(readableWebSocketStream, server, remoteSocketWrapper, log);

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * Wraps a WebSocket in a ReadableStream to handle VLESS chunks.
 * Handles early data if present in the Sec-WebSocket-Protocol header.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            // The client will close the connection if it's done
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener('error', (err) => {
                log('webSocketServer has error');
                controller.error(err);
            });
            
            // Handle early data for 0-RTT
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // No-op
        },

        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// Helper: Safely decode Base64 URL Safe strings to ArrayBuffer
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (e) {
        // Ignore errors on close
    }
}

/**
 * Main VLESS Protocol Logic.
 * Parses the header, authenticates the user, and routes traffic.
 */
async function handleVLESSClient(readableWebSocketStream, webSocket, remoteSocketWrapper, log) {
    let vlessHeader = new Uint8Array(0);
    let chunk = null;
    let isHeaderProcessed = false;
    let remoteConnection = null;
    let writer = null;
    
    // Track usage for this session
    let uploadBytes = 0;
    let downloadBytes = 0;
    let userID = null;

    try {
        const reader = readableWebSocketStream.getReader();

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            
            chunk = value;
            if (!isHeaderProcessed) {
                // Append chunk to header buffer
                const newHeader = new Uint8Array(vlessHeader.length + chunk.byteLength);
                newHeader.set(vlessHeader);
                newHeader.set(new Uint8Array(chunk), vlessHeader.length);
                vlessHeader = newHeader;

                // Try to process the header
                // We need at least 24 bytes for a valid VLESS header with UUID
                if (vlessHeader.length >= 24) {
                    const buffer = vlessHeader.buffer;
                    
                    // Parse UUID to authenticate
                    const version = new Uint8Array(buffer.slice(0, 1))[0];
                    let uuid = [];
                    const uuidBytes = new Uint8Array(buffer.slice(1, 17));
                    for (let i = 0; i < 16; i++) {
                        uuid.push(uuidBytes[i].toString(16).padStart(2, '0'));
                    }
                    const uuidStr = [
                        uuid.slice(0, 4).join(''),
                        uuid.slice(4, 6).join(''),
                        uuid.slice(6, 8).join(''),
                        uuid.slice(8, 10).join(''),
                        uuid.slice(10).join('')
                    ].join('-');

                    // Authenticate via DB
                    const isValid = await verifyUser(Config.DB, uuidStr);
                    if (!isValid) {
                        // Invalid user, close connection
                        log(`Invalid UUID: ${uuidStr}`);
                        return; 
                    }
                    userID = uuidStr;
                    // Parse Option Length (1 byte)
                    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
                    
                    // The command byte is immediately after options
                    // Header structure: [Version][UUID][OptLen][Options][Command][Port][AddrType][Addr]
                    const commandIndex = 18 + optLength;
                    const command = new Uint8Array(buffer.slice(commandIndex, commandIndex + 1))[0];
                    
                    // Port (2 bytes, big endian)
                    const portIndex = commandIndex + 1;
                    const portBuffer = new Uint8Array(buffer.slice(portIndex, portIndex + 2));
                    const remotePort = (portBuffer[0] << 8) | portBuffer[1];
                    
                    // Address Type (1 byte)
                    const addressTypeIndex = portIndex + 2;
                    const addressType = new Uint8Array(buffer.slice(addressTypeIndex, addressTypeIndex + 1))[0];
                    
                    // Parsing Address
                    let addressLength = 0;
                    let addressValue = '';
                    let addressIndex = addressTypeIndex + 1;
                    
                    if (addressType === 1) {
                        // IPv4 (4 bytes)
                        addressLength = 4;
                        addressValue = new Uint8Array(buffer.slice(addressIndex, addressIndex + addressLength)).join('.');
                    } else if (addressType === 2) {
                        // Domain Name (1 byte length + length bytes)
                        addressLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
                        addressIndex += 1; // Move past the length byte
                        addressValue = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + addressLength));
                    } else if (addressType === 3) {
                        // IPv6 (16 bytes)
                        addressLength = 16;
                        const dataView = new DataView(buffer.slice(addressIndex, addressIndex + addressLength));
                        const ipv6 = [];
                        for (let i = 0; i < 8; i++) {
                            ipv6.push(dataView.getUint16(i * 2).toString(16));
                        }
                        addressValue = ipv6.join(':');
                    } else {
                        // Unknown Address Type
                        log(`Unknown Address Type: ${addressType}`);
                        return;
                    }
                    
                    // Check if we have received the full header based on parsed length
                    const currentHeaderLength = addressIndex + addressLength;
                    if (vlessHeader.byteLength < currentHeaderLength) {
                        // Need more data, wait for next chunk
                        continue;
                    }
                    
                    isHeaderProcessed = true;
                    
                    // Extract payload (data after header)
                    const vlessPayload = vlessHeader.slice(currentHeaderLength);
                    
                    // Connect to Remote
                    // Handle IPv6 brackets for connection string if needed
                    const remoteHost = addressValue.includes(':') && !addressValue.startsWith('[') ? `[${addressValue}]` : addressValue;
                    
                    try {
                        // Establish TCP connection to the target
                        // Assuming 'connect' is available from 'cloudflare:sockets' (global or imported)
                        remoteConnection = connect({
                            hostname: remoteHost,
                            port: remotePort
                        });
                    } catch (err) {
                        log(`Connection Failed to ${remoteHost}:${remotePort}`, err);
                        return;
                    }
                    
                    remoteSocketWrapper.value = remoteConnection;
                    writer = remoteConnection.writable.getWriter();
                    
                    // Send VLESS Response Header
                    // Version (1 byte) + AddOns (1 byte, 0)
                    webSocket.send(new Uint8Array([vlessHeader[0], 0]));
                    
                    // Pipe Remote -> WebSocket (Download)
                    // We run this without awaiting to allow bidirectional traffic loop
                    (async () => {
                        try {
                            const reader = remoteConnection.readable.getReader();
                            while(true) {
                                const { value, done } = await reader.read();
                                if (done) break;
                                if (value) {
                                    downloadBytes += value.byteLength;
                                    webSocket.send(value);
                                }
                            }
                        } catch(e) {
                             // Ignore pipe errors (connection closed)
                        }
                    })();
                    
                    // Write Initial Payload from Client -> Remote
                    if (vlessPayload.length > 0) {
                        uploadBytes += vlessPayload.length;
                        await writer.write(vlessPayload);
                    }
                }
            } else {
                // Header already processed, forward raw data chunks
                if (chunk) {
                    uploadBytes += chunk.byteLength;
                    if (writer) {
                        await writer.write(chunk);
                    }
                }
            }
        }
    } catch (error) {
        log('VLESS Handler Error', error);
    } finally {
        // Cleanup and save stats
        if (userID && Config.DB) {
            // Update usage stats in D1 Database
            // Note: Since ctx is not available in this scope, we execute best-effort.
            updateUsage(Config.DB, userID, uploadBytes, downloadBytes).catch(() => {});
        }
        
        if (remoteConnection) {
            try { remoteConnection.close(); } catch(e) {}
        }
        safeCloseWebSocket(webSocket);
    }
}
/**
 * Optional: Scamalytics IP Risk Check
 * Use this function to validate client IPs before establishing outbound connections.
 * Recommended integration: Call inside handleVLESSClient before connect().
 */
async function checkIPRisk(ip) {
    // Skip check if API is not configured
    if (!Config.API || !Config.API.startsWith('http')) return true;
    
    try {
        // Assuming user passes API Key via env or appends to Config.API
        const res = await fetch(`${Config.API}${ip}`, {
            headers: { 'Accept': 'application/json' }
        });
        if (res.ok) {
            const data = await res.json();
            // Block if fraud score is high (e.g., > 75)
            if (data.score && data.score > 75) {
                return false;
            }
        }
        return true; // Fail open (allow) if check fails or API is down
    } catch (e) {
        // console.error("Risk Check Failed:", e);
        return true;
    }
}
