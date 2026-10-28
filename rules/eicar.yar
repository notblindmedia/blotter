// Blotter's own YARA rules live in this folder (every *.yar file is used).
//
// Meta fields Blotter reads:
//   blotter = "malicious" | "suspicious" | "risky" | "hiding"   (how much a match counts)
//   text    = the sentence shown on the result card
//
// This rule recognises the EICAR antivirus test file, so Blotter can show a detection even
// before YARA Forge's rules are downloaded. The test string is split in two on purpose, so this
// file itself doesn't look like the test file to antivirus programs.

rule Blotter_EICAR_test_file
{
    meta:
        blotter = "malicious"
        text = "This is the EICAR antivirus test file. It is harmless, but every scanner is built to treat it as malware."
        description = "EICAR antivirus test file"
    strings:
        $start = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        $name = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $start at 0 and $name and filesize < 200
}
