import { crc32 } from "../src/utils";

describe("crc32", () => {
  test("abcdefg returns expected value", () => {
    const str = "abcdefg";
    const expected = 824863398;
    const actual = crc32(str);
    expect(actual).toEqual(expected);
  });

  test("mnemonic returns expected value", () => {
    // const str = "abcdefg";
    // const expected = 824863398;
    // const actual = crc32(str);
    // expect(actual).toEqual(expected);
  });
});
