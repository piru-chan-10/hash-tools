/**
 * @param data: this is a data which has to be hashed
 * @field k64: this is a array of constants used in the SHA256 algorithm
 * @field k8: this is a array of constants used in the SHA256 algorithm
 * @method padding: pads the data to be hashed
 * @method pre_process: processes the data to be hashed
 * @method digest: computes the SHA-256 hash of the data
 */

class SecureHash256 {
    constructor() {
        // field-constants
        this.k8 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        this.k64 = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
    }

    // bit-operations
    ROTR = (x, n) => ((x >>> n) | (x << (32 - n))) & 0xFFFFFFFF;
    XOR  = (x, y) => x ^ y;
    CH   = (x, y, z) => ((x & y) ^ (~x & z)) & 0xFFFFFFFF;
    MAJ  = (x, y, z) => ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF;
    BSX0 = (x) => (this.ROTR(x, 2)  ^ this.ROTR(x, 13) ^ this.ROTR(x, 22)) & 0xFFFFFFFF;
    BSX1 = (x) => (this.ROTR(x, 6)  ^ this.ROTR(x, 11) ^ this.ROTR(x, 25)) & 0xFFFFFFFF;
    SSX0 = (x) => (this.ROTR(x, 7)  ^ this.ROTR(x, 18) ^ (x >>> 3))        & 0xFFFFFFFF;
    SSX1 = (x) => (this.ROTR(x, 17) ^ this.ROTR(x, 19) ^ (x >>> 10))       & 0xFFFFFFFF;

    digest(msg) {
        let H = [...this.k8];
        let processed_msg = this.pre_process(msg);
        for (let M = 0; M < processed_msg.length; M++) {
            let [a, b, c, d, e, f, g, h] = [...H];
            let W = new Array(64).fill(0);
            for (let i = 0; i < 64; i++) {
                W[i] = i < 16
                    ? processed_msg[M][i]
                    : (this.SSX1(W[i - 2]) + W[i - 7] + this.SSX0(W[i - 15]) + W[i - 16]) & 0xFFFFFFFF;
            }
            for (let t = 0; t < 64; t++) {
                let T1 = (h + this.BSX1(e) + this.CH(e, f, g) + this.k64[t] + W[t]) & 0xFFFFFFFF;
                let T2 = (this.BSX0(a) + this.MAJ(a, b, c)) & 0xFFFFFFFF;
                h = g; g = f; f = e;
                e = (d + T1) & 0xFFFFFFFF;
                d = c; c = b; b = a;
                a = (T1 + T2) & 0xFFFFFFFF;
            }
            H = [
                (H[0] + a) & 0xFFFFFFFF, (H[1] + b) & 0xFFFFFFFF,
                (H[2] + c) & 0xFFFFFFFF, (H[3] + d) & 0xFFFFFFFF,
                (H[4] + e) & 0xFFFFFFFF, (H[5] + f) & 0xFFFFFFFF,
                (H[6] + g) & 0xFFFFFFFF, (H[7] + h) & 0xFFFFFFFF
            ];
        }
        return H.map(i => (i >>> 0).toString(16).padStart(8, "0")).join("");
    }

    // integer to binary
    get_int_to_binary(num, padding = 8) {
        return num.toString(2).padStart(padding, "0");
    }

    // padding-process
    padding(msg) {
        let bytes = new TextEncoder().encode(msg);
        let l = bytes.length * 8;
        let res = [...bytes].map(b => b.toString(2).padStart(8, "0")).join("");
        res += "1";
        let k = (448 - (l + 1) % 512 + 512) % 512;
        res += "0".repeat(k);
        res += this.get_int_to_binary(l, 64);
        return res;
    }

    // chunk parsing
    parse_chunks(msg) {
        let chunk = [];
        for (let i = 0; i < msg.length; i += 512) {
            chunk.push(msg.slice(i, i + 512));
        }
        return chunk;
    }

    // parse-words
    parse_words(chunk) {
        let words = [];
        for (let i = 0; i < chunk.length; i += 32) {
            words.push(parseInt(chunk.slice(i, i + 32), 2));
        }
        return words;
    }

    pre_process(msg) {
        return this.parse_chunks(this.padding(msg)).map(i => this.parse_words(i));
    }
}
