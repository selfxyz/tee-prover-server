pragma circom 2.1.9;

include "../dsc.circom";

component main { public [ merkle_root ] } = DSC(10, 120, 35, 120, 35, 1664, 256, 12);