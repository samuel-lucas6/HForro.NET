using HForroDotNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HForroDotNetTests;

[TestClass]
public class HForroTests
{
    // expected is based on https://github.com/samuel-lucas6/Forro.NET passing official test vectors
    // key and nonce are from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    [TestMethod]
    public void TestVector()
    {
        Span<byte> expected = Convert.FromHexString("9754128339bd105377908eb53d7f238e7b3732cc48383052d35fd94c943db866");
        Span<byte> key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Span<byte> nonce = Convert.FromHexString("000000090000004a0000000031415927");
        Span<byte> outputKeyingMaterial = stackalloc byte[HForro.OutputSize];
        HForro.DeriveKey(outputKeyingMaterial, key, nonce);
        Assert.IsTrue(outputKeyingMaterial.SequenceEqual(expected));
    }
}