/*
    HForró.NET: A .NET implementation of HForró.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace HForroDotNet;

public static class HForro
{
    public const int OutputSize = 32;
    public const int KeySize = 32;
    public const int NonceSize = 16;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce)
    {
        if (outputKeyingMaterial.Length != OutputSize) { throw new ArgumentOutOfRangeException(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, $"{nameof(outputKeyingMaterial)} must be {OutputSize} bytes long."); }
        if (inputKeyingMaterial.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, $"{nameof(inputKeyingMaterial)} must be {KeySize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        
        uint x0 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 0);
        uint x1 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 4);
        uint x2 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 8);
        uint x3 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 12);
        uint x4 = ReadUInt32LittleEndian(nonce, offset: 0);
        uint x5 = ReadUInt32LittleEndian(nonce, offset: 4);
        uint x6 = 0x746C6F76;
        uint x7 = 0x61616461;
        uint x8 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 16);
        uint x9 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 20);
        uint x10 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 24);
        uint x11 = ReadUInt32LittleEndian(inputKeyingMaterial, offset: 28);
        uint x12 = ReadUInt32LittleEndian(nonce, offset: 8);
        uint x13 = ReadUInt32LittleEndian(nonce, offset: 12);
        uint x14 = 0x72626173;
        uint x15 = 0x61636E61;
        
        for (int i = 0; i < 7; i++) {
            QuarterRound(ref x0, ref x4, ref x8, ref x12, ref x3);
            QuarterRound(ref x1, ref x5, ref x9, ref x13, ref x0);
            QuarterRound(ref x2, ref x6, ref x10, ref x14, ref x1);
            QuarterRound(ref x3, ref x7, ref x11, ref x15, ref x2);
            QuarterRound(ref x0, ref x5, ref x10, ref x15, ref x3);
            QuarterRound(ref x1, ref x6, ref x11, ref x12, ref x0);
            QuarterRound(ref x2, ref x7, ref x8, ref x13, ref x1);
            QuarterRound(ref x3, ref x4, ref x9, ref x14, ref x2);
        }
        
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 0, x6);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 4, x7);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 8, x14);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 12, x15);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 16, x4);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 20, x5);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 24, x12);
        WriteUInt32LittleEndian(outputKeyingMaterial, offset: 28, x13);
    }
    
    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source, int offset)
    {
        return source[offset] | (uint) source[offset + 1] << 8 | (uint) source[offset + 2] << 16 | (uint) source[offset + 3] << 24;
    }
    
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e)
    {
        d += e;
        c ^= d;
        b += c;
        b = RotateLeft(b, 10);
        a += b;
        e ^= a;
        d += e;
        d = RotateLeft(d, 27);
        c += d;
        b ^= c;
        a += b;
        a = RotateLeft(a, 8);
    }
    
    private static uint RotateLeft(uint a, int b)
    {
        return (a << b) | (a >> (32 - b));
    }
    
    private static void WriteUInt32LittleEndian(Span<byte> destination, int offset, uint value)
    {
        destination[offset] = (byte) value;
        destination[offset + 1] = (byte) (value >> 8);
        destination[offset + 2] = (byte) (value >> 16);
        destination[offset + 3] = (byte) (value >> 24);
    }
}