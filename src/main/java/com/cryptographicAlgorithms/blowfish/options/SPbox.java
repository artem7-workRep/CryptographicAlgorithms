package main.java.com.cryptographicAlgorithms.blowfish.options;

import main.java.com.cryptographicAlgorithms.blowfish.AdditionKeys;
import main.java.com.cryptographicAlgorithms.blowfish.RandomNumbers;

public final class SPbox {
    private long[] ChangedSBox0;
    private long[] ChangedSBox1;
    private long[] ChangedSBox2;
    private long[] ChangedSBox3;
    private long[] ChangedPArray;
    private final AdditionKeys key;
    private RandomNumbers randomNumbers;

    private final long[] sBox0 = {
            0xD1310BA6L, 0x98DFB5ACL, 0x2FFD72DBL, 0xD01ADFB7L,
            0xB8E1AFEDL, 0x6A267E96L, 0xBA7C9045L, 0xF12C7F99L,
            0x24A19947L, 0xB3916CF7L, 0x0801F2E2L, 0x858EFC16L,
            0x636920D8L, 0x71574E69L, 0xA458FEA3L, 0xF4933D7EL,
            0x0D95748FL, 0x728EB658L, 0x718BCD58L, 0x82154AEEL,
            0x7B54A41DL, 0xC25A59B5L, 0x9C30D539L, 0x2AF26013L,
            0xC5D1B023L, 0x286085F0L, 0xCA417918L, 0xB8DB38EFL,
            0x8E79DCB0L, 0x603A180EL, 0x6C9E0E8BL, 0xB01E8A3EL,
            0xD71577C1L, 0xBD314B27L, 0x78AF2FDAL, 0x55605C60L,
            0xE65525F3L, 0xAA55AB94L, 0x57489862L, 0x63E81440L,
            0x55CA396AL, 0x2AAB10B6L, 0xB4CC5C34L, 0x1141E8CEL,
            0xA15486AFL, 0x7C72E993L, 0xB3EE1411L, 0x636FBC2AL,
            0x2BA9C55DL, 0x741831F6L, 0xCE5C3E16L, 0x9B87931EL,
            0xAFD6BA33L, 0x6C24CF5CL, 0x7A325381L, 0x28958677L,
            0x3B8F4898L, 0x6B4BB9AFL, 0xC4BFE81BL, 0x66282193L,
            0x61D809CCL, 0xFB21A991L, 0x487CAC60L, 0x5DEC8032L,
            0xEF845D5DL, 0xE98575B1L, 0xDC262302L, 0xEB651B88L,
            0x23893E81L, 0xD396ACC5L, 0x0F6D6FF3L, 0x83F44239L,
            0x2E0B4482L, 0xA4842004L, 0x69C8F04AL, 0x9E1F9B5EL,
            0x21C66842L, 0xF6E96C9AL, 0x670C9C61L, 0xABD388F0L,
            0x6A51A0D2L, 0xD8542F68L, 0x960FA728L, 0xAB5133A3L,
            0x6EEF0B6CL, 0x137A3BE4L, 0xBA3BF050L, 0x7EFB2A98L,
            0xA1F1651DL, 0x39AF0176L, 0x66CA593EL, 0x82430E88L,
            0x8CEE8619L, 0x456F9FB4L, 0x7D84A5C3L, 0x3B8B5EBEL,
            0xE06F75D8L, 0x85C12073L, 0x401A449FL, 0x56C16AA6L,
            0x4ED3AA62L, 0x363F7706L, 0x1BFEDF72L, 0x429B023DL,
            0x37D0D724L, 0xD00A1248L, 0xDB0FEAD3L, 0x49F1C09BL,
            0x075372C9L, 0x80991B7BL, 0x25D479D8L, 0xF6E8DEF7L,
            0xE3FE501AL, 0xB6794C3BL, 0x976CE0BDL, 0x04C006BAL,
            0xC1A94FB6L, 0x409F60C4L, 0x5E5C9EC2L, 0x196A2463L,
            0x68FB6FAFL, 0x3E6C53B5L, 0x1339B2EBL, 0x3B52EC6FL,
            0x6DFC511FL, 0x9B30952CL, 0xCC814544L, 0xAF5EBD09L,
            0xBEE3D004L, 0xDE334AFDL, 0x660F2807L, 0x192E4BB3L,
            0xC0CBA857L, 0x45C8740FL, 0xD20B5F39L, 0xB9D3FBDBL,
            0x5579C0BDL, 0x1A60320AL, 0xD6A100C6L, 0x402C7279L,
            0x679F25FEL, 0xFB1FA3CCL, 0x8EA5E9F8L, 0xDB3222F8L,
            0x3C7516DFL, 0xFD616B15L, 0x2F501EC8L, 0xAD0552ABL,
            0x323DB5FAL, 0xFD238760L, 0x53317B48L, 0x3E00DF82L,
            0x9E5C57BBL, 0xCA6F8CA0L, 0x1A87562EL, 0xDF1769DBL,
            0xD542A8F6L, 0x287EFFC3L, 0xAC6732C6L, 0x8C4F5573L,
            0x695B27B0L, 0xBBCA58C8L, 0xE1FFA35DL, 0xB8F011A0L,
            0x10FA3D98L, 0xFD2183B8L, 0x4AFCB56CL, 0x2DD1D35BL,
            0x9A53E479L, 0xB6F84565L, 0xD28E49BCL, 0x4BFB9790L,
            0xE1DDF2DAL, 0xA4CB7E33L, 0x62FB1341L, 0xCEE4C6E8L,
            0xEF20CADAL, 0x36774C01L, 0xD07E9EFEL, 0x2BF11FB4L,
            0x95DBDA4DL, 0xAE909198L, 0xEAAD8E71L, 0x6B93D5A0L,
            0xD08ED1D0L, 0xAFC725E0L, 0x8E3C5B2FL, 0x8E7594B7L,
            0x8FF6E2FBL, 0xF2122B64L, 0x8888B812L, 0x900DF01CL,
            0x4FAD5EA0L, 0x688FC31CL, 0xD1CFF191L, 0xB3A8C1ADL,
            0x2F2F2218L, 0xBE0E1777L, 0xEA752DFEL, 0x8B021FA1L,
            0xE5A0CC0FL, 0xB56F74E8L, 0x18ACF3D6L, 0xCE89E299L,
            0xB4A84FE0L, 0xFD13E0B7L, 0x7CC43B81L, 0xD2ADA8D9L,
            0x165FA266L, 0x80957705L, 0x93CC7314L, 0x211A1477L,
            0xE6AD2065L, 0x77B5FA86L, 0xC75442F5L, 0xFB9D35CFL,
            0xEBCDAF0CL, 0x7B3E89A0L, 0xD6411BD3L, 0xAE1E7E49L,
            0x00250E2DL, 0x2071B35EL, 0x226800BBL, 0x57B8E0AFL,
            0x2464369BL, 0xF009B91EL, 0x5563911DL, 0x59DFA6AAL,
            0x78C14389L, 0xD95A537FL, 0x207D5BA2L, 0x02E5B9C5L,
            0x83260376L, 0x6295CFA9L, 0x11C81968L, 0x4E734A41L,
            0xB3472DCAL, 0x7B14A94AL, 0x1B510052L, 0x9A532915L,
            0xD60F573FL, 0xBC9BC6E4L, 0x2B60A476L, 0x81E67400L,
            0x08BA6FB5L, 0x571BE91FL, 0xF296EC6BL, 0x2A0DD915L,
            0xB6636521L, 0xE7B9F9B6L, 0xFF34052EL, 0xC5855664L,
            0x53B02D5DL, 0xA99F8FA1L, 0x08BA4799L, 0x6E85076AL};

    private final long[] sBox1 = {
            0xD1310BA6L, 0x98DFB5ACL, 0x2FFD72DBL, 0xD01ADFB7L,
            0xB8E1AFEDL, 0x6A267E96L, 0xBA7C9045L, 0xF12C7F99L,
            0x24A19947L, 0xB3916CF7L, 0x0801F2E2L, 0x858EFC16L,
            0x636920D8L, 0x71574E69L, 0xA458FEA3L, 0xF4933D7EL,
            0x0D95748FL, 0x728EB658L, 0x718BCD58L, 0x82154AEEL,
            0x7B54A41DL, 0xC25A59B5L, 0x9C30D539L, 0x2AF26013L,
            0xC5D1B023L, 0x286085F0L, 0xCA417918L, 0xB8DB38EFL,
            0x8E79DCB0L, 0x603A180EL, 0x6C9E0E8BL, 0xB01E8A3EL,
            0xD71577C1L, 0xBD314B27L, 0x78AF2FDAL, 0x55605C60L,
            0xE65525F3L, 0xAA55AB94L, 0x57489862L, 0x63E81440L,
            0x55CA396AL, 0x2AAB10B6L, 0xB4CC5C34L, 0x1141E8CEL,
            0xA15486AFL, 0x7C72E993L, 0xB3EE1411L, 0x636FBC2AL,
            0x2BA9C55DL, 0x741831F6L, 0xCE5C3E16L, 0x9B87931EL,
            0xAFD6BA33L, 0x6C24CF5CL, 0x7A325381L, 0x28958677L,
            0x3B8F4898L, 0x6B4BB9AFL, 0xC4BFE81BL, 0x66282193L,
            0x61D809CCL, 0xFB21A991L, 0x487CAC60L, 0x5DEC8032L,
            0xEF845D5DL, 0xE98575B1L, 0xDC262302L, 0xEB651B88L,
            0x23893E81L, 0xD396ACC5L, 0x0F6D6FF3L, 0x83F44239L,
            0x2E0B4482L, 0xA4842004L, 0x69C8F04AL, 0x9E1F9B5EL,
            0x21C66842L, 0xF6E96C9AL, 0x670C9C61L, 0xABD388F0L,
            0x6A51A0D2L, 0xD8542F68L, 0x960FA728L, 0xAB5133A3L,
            0x6EEF0B6CL, 0x137A3BE4L, 0xBA3BF050L, 0x7EFB2A98L,
            0xA1F1651DL, 0x39AF0176L, 0x66CA593EL, 0x82430E88L,
            0x8CEE8619L, 0x456F9FB4L, 0x7D84A5C3L, 0x3B8B5EBEL,
            0xE06F75D8L, 0x85C12073L, 0x401A449FL, 0x56C16AA6L,
            0x4ED3AA62L, 0x363F7706L, 0x1BFEDF72L, 0x429B023DL,
            0x37D0D724L, 0xD00A1248L, 0xDB0FEAD3L, 0x49F1C09BL,
            0x075372C9L, 0x80991B7BL, 0x25D479D8L, 0xF6E8DEF7L,
            0xE3FE501AL, 0xB6794C3BL, 0x976CE0BDL, 0x04C006BAL,
            0xC1A94FB6L, 0x409F60C4L, 0x5E5C9EC2L, 0x196A2463L,
            0x68FB6FAFL, 0x3E6C53B5L, 0x1339B2EBL, 0x3B52EC6FL,
            0x6DFC511FL, 0x9B30952CL, 0xCC814544L, 0xAF5EBD09L,
            0xBEE3D004L, 0xDE334AFDL, 0x660F2807L, 0x192E4BB3L,
            0xC0CBA857L, 0x45C8740FL, 0xD20B5F39L, 0xB9D3FBDBL,
            0x5579C0BDL, 0x1A60320AL, 0xD6A100C6L, 0x402C7279L,
            0x679F25FEL, 0xFB1FA3CCL, 0x8EA5E9F8L, 0xDB3222F8L,
            0x3C7516DFL, 0xFD616B15L, 0x2F501EC8L, 0xAD0552ABL,
            0x323DB5FAL, 0xFD238760L, 0x53317B48L, 0x3E00DF82L,
            0x9E5C57BBL, 0xCA6F8CA0L, 0x1A87562EL, 0xDF1769DBL,
            0xD542A8F6L, 0x287EFFC3L, 0xAC6732C6L, 0x8C4F5573L,
            0x695B27B0L, 0xBBCA58C8L, 0xE1FFA35DL, 0xB8F011A0L,
            0x10FA3D98L, 0xFD2183B8L, 0x4AFCB56CL, 0x2DD1D35BL,
            0x9A53E479L, 0xB6F84565L, 0xD28E49BCL, 0x4BFB9790L,
            0xE1DDF2DAL, 0xA4CB7E33L, 0x62FB1341L, 0xCEE4C6E8L,
            0xEF20CADAL, 0x36774C01L, 0xD07E9EFEL, 0x2BF11FB4L,
            0x95DBDA4DL, 0xAE909198L, 0xEAAD8E71L, 0x6B93D5A0L,
            0xD08ED1D0L, 0xAFC725E0L, 0x8E3C5B2FL, 0x8E7594B7L,
            0x8FF6E2FBL, 0xF2122B64L, 0x8888B812L, 0x900DF01CL,
            0x4FAD5EA0L, 0x688FC31CL, 0xD1CFF191L, 0xB3A8C1ADL,
            0x2F2F2218L, 0xBE0E1777L, 0xEA752DFEL, 0x8B021FA1L,
            0xE5A0CC0FL, 0xB56F74E8L, 0x18ACF3D6L, 0xCE89E299L,
            0xB4A84FE0L, 0xFD13E0B7L, 0x7CC43B81L, 0xD2ADA8D9L,
            0x165FA266L, 0x80957705L, 0x93CC7314L, 0x211A1477L,
            0xE6AD2065L, 0x77B5FA86L, 0xC75442F5L, 0xFB9D35CFL,
            0xEBCDAF0CL, 0x7B3E89A0L, 0xD6411BD3L, 0xAE1E7E49L,
            0x00250E2DL, 0x2071B35EL, 0x226800BBL, 0x57B8E0AFL,
            0x2464369BL, 0xF009B91EL, 0x5563911DL, 0x59DFA6AAL,
            0x78C14389L, 0xD95A537FL, 0x207D5BA2L, 0x02E5B9C5L,
            0x83260376L, 0x6295CFA9L, 0x11C81968L, 0x4E734A41L,
            0xB3472DCAL, 0x7B14A94AL, 0x1B510052L, 0x9A532915L,
            0xD60F573FL, 0xBC9BC6E4L, 0x2B60A476L, 0x81E67400L,
            0x08BA6FB5L, 0x571BE91FL, 0xF296EC6BL, 0x2A0DD915L,
            0xB6636521L, 0xE7B9F9B6L, 0xFF34052EL, 0xC5855664L,
            0x53B02D5DL, 0xA99F8FA1L, 0x08BA4799L, 0x6E85076AL};

    private final long[] sBox2 = {
            0xE93D5A68L, 0x948140F7L, 0xF64C261CL, 0x94692934L,
            0x411520F7L, 0x7602D4F7L, 0xBCF46B2EL, 0xD4A20068L,
            0xD4082471L, 0x3320F46AL, 0x43B7D4B7L, 0x500061AFL,
            0x1E39F62EL, 0x97244546L, 0x14214F74L, 0xBF8B8840L,
            0x4D95FC1DL, 0x96B591AFL, 0x70F4DDD3L, 0x66A02F45L,
            0xBFBC09ECL, 0x03BD9785L, 0x7FAC6DD0L, 0x31CB8504L,
            0x96EB27B3L, 0x55FD3941L, 0xDA2547E6L, 0xABCA0A9AL,
            0x28507825L, 0x530429F4L, 0x0A2C86DAL, 0xE9B66DFBL,
            0x68DC1462L, 0xD7486900L, 0x680EC0A4L, 0x27A18DEEL,
            0x4F3FFEA2L, 0xE887AD8CL, 0xB58CE006L, 0x7AF4D6B6L,
            0xAACE1E7CL, 0xD3375FECL, 0xCE78A399L, 0x406B2A42L,
            0x20FE9E35L, 0xD9F385B9L, 0xEE39D7ABL, 0x3B124E8BL,
            0x1DC9FAF7L, 0x4B6D1856L, 0x26A36631L, 0xEAE397B2L,
            0x3A6EFA74L, 0xDD5B4332L, 0x6841E7F7L, 0xCA7820FBL,
            0xFB0AF54EL, 0xD8FEB397L, 0x454056ACL, 0xBA489527L,
            0x55533A3AL, 0x20838D87L, 0xFE6BA9B7L, 0xD096954BL,
            0x55A867BCL, 0xA1159A58L, 0xCCA92963L, 0x99E1DB33L,
            0xA62A4A56L, 0x3F3125F9L, 0x5EF47E1CL, 0x9029317CL,
            0xFDF8E802L, 0x04272F70L, 0x80BB155CL, 0x05282CE3L,
            0x95C11548L, 0xE4C66D22L, 0x48C1133FL, 0xC70F86DCL,
            0x07F9C9EEL, 0x41041F0FL, 0x404779A4L, 0x5D886E17L,
            0x325F51EBL, 0xD59BC0D1L, 0xF2BCC18FL, 0x41113564L,
            0x257B7834L, 0x602A9C60L, 0xDFF8E8A3L, 0x1F636C1BL,
            0x0E12B4C2L, 0x02E1329EL, 0xAF664FD1L, 0xCAD18115L,
            0x6B2395E0L, 0x333E92E1L, 0x3B240B62L, 0xEEBEB922L,
            0x85B2A20EL, 0xE6BA0D99L, 0xDE720C8CL, 0x2DA2F728L,
            0xD0127845L, 0x95B794FDL, 0x647D0862L, 0xE7CCF5F0L,
            0x5449A36FL, 0x877D48FAL, 0xC39DFD27L, 0xF33E8D1EL,
            0x0A476341L, 0x992EFF74L, 0x3A6F6EABL, 0xF4F8FD37L,
            0xA812DC60L, 0xA1EBDDF8L, 0x991BE14CL, 0xDB6E6B0DL,
            0xC67B5510L, 0x6D672C37L, 0x2765D43BL, 0xDCD0E804L,
            0xF1290DC7L, 0xCC00FFA3L, 0xB5390F92L, 0x690FED0BL,
            0x667B9FFBL, 0xCEDB7D9CL, 0xA091CF0BL, 0xD9155EA3L,
            0xBB132F88L, 0x515BAD24L, 0x7B9479BFL, 0x763BD6EBL,
            0x37392EB3L, 0xCC115979L, 0x8026E297L, 0xF42E312DL,
            0x6842ADA7L, 0xC66A2B3BL, 0x12754CCCL, 0x782EF11CL,
            0x6A124237L, 0xB79251E7L, 0x06A1BBE6L, 0x4BFB6350L,
            0x1A6B1018L, 0x11CAEDFAL, 0x3D25BDD8L, 0xE2E1C3C9L,
            0x44421659L, 0x0A121386L, 0xD90CEC6EL, 0xD5ABEA2AL,
            0x64AF674EL, 0xDA86A85FL, 0xBEBFE988L, 0x64E4C3FEL,
            0x9DBC8057L, 0xF0F7C086L, 0x60787BF8L, 0x6003604DL,
            0xD1FD8346L, 0xF6381FB0L, 0x7745AE04L, 0xD736FCCCL,
            0x83426B33L, 0xF01EAB71L, 0xB0804187L, 0x3C005E5FL,
            0x77A057BEL, 0xBDE8AE24L, 0x55464299L, 0xBF582E61L,
            0x4E58F48FL, 0xF2DDFDA2L, 0xF474EF38L, 0x8789BDC2L,
            0x5366F9C3L, 0xC8B38E74L, 0xB475F255L, 0x46FCD9B9L,
            0x7AEB2661L, 0x8B1DDF84L, 0x846A0E79L, 0x915F95E2L,
            0x466E598EL, 0x20B45770L, 0x8CD55591L, 0xC902DE4CL,
            0xB90BACE1L, 0xBB8205D0L, 0x11A86248L, 0x7574A99EL,
            0xB77F19B6L, 0xE0A9DC09L, 0x662D09A1L, 0xC4324633L,
            0xE85A1F02L, 0x09F0BE8CL, 0x4A99A025L, 0x1D6EFE10L,
            0x1AB93D1DL, 0x0BA5A4DFL, 0xA186F20FL, 0x2868F169L,
            0xDCB7DA83L, 0x573906FEL, 0xA1E2CE9BL, 0x4FCD7F52L,
            0x50115E01L, 0xA70683FAL, 0xA002B5C4L, 0x0DE6D027L,
            0x9AF88C27L, 0x773F8641L, 0xC3604C06L, 0x61A806B5L,
            0xF0177A28L, 0xC0F586E0L, 0x006058AAL, 0x30DC7D62L,
            0x11E69ED7L, 0x2338EA63L, 0x53C2DD94L, 0xC2C21634L,
            0xBBCBEE56L, 0x90BCB6DEL, 0xEBFC7DA1L, 0xCE591D76L,
            0x6F05E409L, 0x4B7C0188L, 0x39720A3DL, 0x7C927C24L,
            0x86E3725FL, 0x724D9DB9L, 0x1AC15BB4L, 0xD39EB8FCL,
            0xED545578L, 0x08FCA5B5L, 0xD83D7CD3L, 0x4DAD0FC4L,
            0x1E50EF5EL, 0xB161E6F8L, 0xA28514D9L, 0x6C51133CL,
            0x6FD5C7E7L, 0x56E14EC4L, 0x362ABFCEL, 0xDDC6C837L,
            0xD79A3234L, 0x92638212L, 0x670EFA8EL, 0x406000E0L};

    private final long[] sBox3 = {
            0x3A39CE37L, 0xD3FAF5CFL, 0xABC27737L, 0x5AC52D1BL,
            0x5CB0679EL, 0x4FA33742L, 0xD3822740L, 0x99BC9BBEL,
            0xD5118E9DL, 0xBF0F7315L, 0xD62D1C7EL, 0xC700C47BL,
            0xB78C1B6BL, 0x21A19045L, 0xB26EB1BEL, 0x6A366EB4L,
            0x5748AB2FL, 0xBC946E79L, 0xC6A376D2L, 0x6549C2C8L,
            0x530FF8EEL, 0x468DDE7DL, 0xD5730A1DL, 0x4CD04DC6L,
            0x2939BBDBL, 0xA9BA4650L, 0xAC9526E8L, 0xBE5EE304L,
            0xA1FAD5F0L, 0x6A2D519AL, 0x63EF8CE2L, 0x9A86EE22L,
            0xC089C2B8L, 0x43242EF6L, 0xA51E03AAL, 0x9CF2D0A4L,
            0x83C061BAL, 0x9BE96A4DL, 0x8FE51550L, 0xBA645BD6L,
            0x2826A2F9L, 0xA73A3AE1L, 0x4BA99586L, 0xEF5562E9L,
            0xC72FEFD3L, 0xF752F7DAL, 0x3F046F69L, 0x77FA0A59L,
            0x80E4A915L, 0x87B08601L, 0x9B09E6ADL, 0x3B3EE593L,
            0xE990FD5AL, 0x9E34D797L, 0x2CF0B7D9L, 0x022B8B51L,
            0x96D5AC3AL, 0x017DA67DL, 0xD1CF3ED6L, 0x7C7D2D28L,
            0x1F9F25CFL, 0xADF2B89BL, 0x5AD6B472L, 0x5A88F54CL,
            0xE029AC71L, 0xE019A5E6L, 0x47B0ACFDL, 0xED93FA9BL,
            0xE8D3C48DL, 0x283B57CCL, 0xF8D56629L, 0x79132E28L,
            0x785F0191L, 0xED756055L, 0xF7960E44L, 0xE3D35E8CL,
            0x15056DD4L, 0x88F46DBAL, 0x03A16125L, 0x0564F0BDL,
            0xC3EB9E15L, 0x3C9057A2L, 0x97271AECL, 0xA93A072AL,
            0x1B3F6D9BL, 0x1E6321F5L, 0xF59C66FBL, 0x26DCF319L,
            0x7533D928L, 0xB155FDF5L, 0x03563482L, 0x8ABA3CBBL,
            0x28517711L, 0xC20AD9F8L, 0xABCC5167L, 0xCCAD925FL,
            0x4DE81751L, 0x3830DC8EL, 0x379D5862L, 0x9320F991L,
            0xEA7A90C2L, 0xFB3E7BCEL, 0x5121CE64L, 0x774FBE32L,
            0xA8B6E37EL, 0xC3293D46L, 0x48DE5369L, 0x6413E680L,
            0xA2AE0810L, 0xDD6DB224L, 0x69852DFDL, 0x09072166L,
            0xB39A460AL, 0x6445C0DDL, 0x586CDECFL, 0x1C20C8AEL,
            0x5BBEF7DDL, 0x1B588D40L, 0xCCD2017FL, 0x6BB4E3BBL,
            0xDDA26A7EL, 0x3A59FF45L, 0x3E350A44L, 0xBCB4CDD5L,
            0x72EACEA8L, 0xFA6484BBL, 0x8D6612AEL, 0xBF3C6F47L,
            0xD29BE463L, 0x542F5D9EL, 0xAEC2771BL, 0xF64E6370L,
            0x740E0D8DL, 0xE75B1357L, 0xF8721671L, 0xAF537D5DL,
            0x4040CB08L, 0x4EB4E2CCL, 0x34D2466AL, 0x0115AF84L,
            0xE1B00428L, 0x95983A1DL, 0x06B89FB4L, 0xCE6EA048L,
            0x6F3F3B82L, 0x3520AB82L, 0x011A1D4BL, 0x277227F8L,
            0x611560B1L, 0xE7933FDCL, 0xBB3A792BL, 0x344525BDL,
            0xA08839E1L, 0x51CE794BL, 0x2F32C9B7L, 0xA01FBAC9L,
            0xE01CC87EL, 0xBCC7D1F6L, 0xCF0111C3L, 0xA1E8AAC7L,
            0x1A908749L, 0xD44FBD9AL, 0xD0DADECBL, 0xD50ADA38L,
            0x0339C32AL, 0xC6913667L, 0x8DF9317CL, 0xE0B12B4FL,
            0xF79E59B7L, 0x43F5BB3AL, 0xF2D519FFL, 0x27D9459CL,
            0xBF97222CL, 0x15E6FC2AL, 0x0F91FC71L, 0x9B941525L,
            0xFAE59361L, 0xCEB69CEBL, 0xC2A86459L, 0x12BAA8D1L,
            0xB6C1075EL, 0xE3056A0CL, 0x10D25065L, 0xCB03A442L,
            0xE0EC6E0EL, 0x1698DB3BL, 0x4C98A0BEL, 0x3278E964L,
            0x9F1F9532L, 0xE0D392DFL, 0xD3A0342BL, 0x8971F21EL,
            0x1B0A7441L, 0x4BA3348CL, 0xC5BE7120L, 0xC37632D8L,
            0xDF359F8DL, 0x9B992F2EL, 0xE60B6F47L, 0x0FE3F11DL,
            0xE54CDA54L, 0x1EDAD891L, 0xCE6279CFL, 0xCD3E7E6FL,
            0x1618B166L, 0xFD2C1D05L, 0x848FD2C5L, 0xF6FB2299L,
            0xF523F357L, 0xA6327623L, 0x93A83531L, 0x56CCCD02L,
            0xACF08162L, 0x5A75EBB5L, 0x6E163697L, 0x88D273CCL,
            0xDE966292L, 0x81B949D0L, 0x4C50901BL, 0x71C65614L,
            0xE6C6C7BDL, 0x327A140AL, 0x45E1D006L, 0xC3F27B9AL,
            0xC9AA53FDL, 0x62A80F00L, 0xBB25BFE2L, 0x35BDD2F6L,
            0x71126905L, 0xB2040222L, 0xB6CBCF7CL, 0xCD769C2BL,
            0x53113EC0L, 0x1640E3D3L, 0x38ABBD60L, 0x2547ADF0L,
            0xBA38209CL, 0xF746CE76L, 0x77AFA1C5L, 0x20756060L,
            0x85CBFE4EL, 0x8AE88DD8L, 0x7AAAF9B0L, 0x4CF9AA7EL,
            0x1948C25CL, 0x02FB8A8CL, 0x01C36AE4L, 0xD6EBE1F9L,
            0x90D4F869L, 0xA65CDEA0L, 0x3F09252DL, 0xC208E69FL,
            0xB74E6132L, 0xCE77E25BL, 0x578FDFE3L, 0x3AC372E6L};
    private final long[] pArray = {
            0x243F6A88L, 0x85A308D3L, 0x13198A2EL, 0x03707344L,
            0xA4093822L, 0x299F31D0L, 0x082EFA98L, 0xEC4E6C89L,
            0x452821E6L, 0x38D01377L, 0xBE5466CFL, 0x34E90C6CL,
            0xC0AC29B7L, 0xC97C50DDL, 0x3F84D5B5L, 0xB5470917L,
            0x9216D5D9L, 0x8979FB1BL};

    public long[] getChangedSBox0() {
        return ChangedSBox0;
    }

    public long[] getChangedSBox1() {
        return ChangedSBox1;
    }

    public long[] getChangedSBox2() {
        return ChangedSBox2;
    }

    public long[] getChangedSBox3() {
        return ChangedSBox3;
    }

    public long[] getChangedPArray() {
        return ChangedPArray;
    }

    /**
     *
     * @param key   Секретный ключ, необходимый для расширения подключей
     *              При передаче ТОЛЬКО закрытого ключа, S и P блоки заполняются
     *              значениями числа Pi по умолчанию (те которые определены выше).
     */
    public SPbox(AdditionKeys key) {
        this.key = key;
        ChangedPArray = new long[18];
        System.arraycopy(pArray, 0, ChangedPArray, 0, 18);

        ChangedSBox0 = new long[256];
        System.arraycopy(sBox0, 0, ChangedSBox0, 0, 256);

        ChangedSBox1 = new long[256];
        System.arraycopy(sBox1, 0, ChangedSBox1, 0, 256);

        ChangedSBox2 = new long[256];
        System.arraycopy(sBox2, 0, ChangedSBox2, 0, 256);

        ChangedSBox3 = new long[256];
        System.arraycopy(sBox3, 0, ChangedSBox3, 0, 256);
    }

    /**
     *
     * @param key               Секретный ключ, необходимый для расширения подключей
     * @param randomNumbers     Объект-реализация интерфейса. Подразумевает, что обьект
     *                          возвращает 32-битные числа, которыми на начальном этапе
     *                          заполняются S,P блоки
     */
    public SPbox(AdditionKeys key, RandomNumbers randomNumbers) {
        this.key = key;
        ChangedPArray = new long[18];
        for (int i = 0; i < 18; i++) {
            ChangedPArray[i] = randomNumbers.ret32BitNumber();
        }
        for (int i = 0; i < 256; i++) {
            ChangedSBox0[i] = randomNumbers.ret32BitNumber();
        }
        for (int i = 0; i < 256; i++) {
            ChangedSBox1[i] = randomNumbers.ret32BitNumber();
        }
        for (int i = 0; i < 256; i++) {
            ChangedSBox2[i] = randomNumbers.ret32BitNumber();
        }
        for (int i = 0; i < 256; i++) {
            ChangedSBox3[i] = randomNumbers.ret32BitNumber();
        }
    }

    private String retKeyInBinaryView(char[] data) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 36; i++) {
            String temp = String.format("%16s", Integer.toBinaryString(data[i])).replace(' ','0');
            result.append(temp);
        }
        return result.toString();
    }

    /**
     * Метод для расширение ключей
     */
    public void initKey() {
        changeParray();
        keyExpansion();
    }

    /**
     * Изменение P-блоков
     * Xor к значению P[1] и первым 32 битам ключа
     */
    private void changeParray() {
        String byteOfKey             = retKeyInBinaryView(this.key.keyToCharArray());
        int    indexStartOfByteOfKey = 0;
        int    indexEndOfByteOfKey   = 32;
        for (int i = 0; i < 18; i++) {
            ChangedPArray[i] = ChangedPArray[i] ^ Long.parseLong(byteOfKey.substring(
                    indexStartOfByteOfKey, indexEndOfByteOfKey), 2);
            indexStartOfByteOfKey += 32;
            indexEndOfByteOfKey += 32;
        }
    }

    private void keyExpansion() {
        long a = 0L;
        for (int i = 0; i < 18; i += 2) {
            a = encrypt(a);
            ChangedPArray[i] = trim(a >>> 32);
            ChangedPArray[i + 1] = trim(a);
        }

        for (int i = 0; i < 256; i += 2) {
            a = encrypt(a);
            ChangedSBox0[i] = trim(a >>> 32);
            ChangedSBox0[i + 1] = trim(a);
        }

        for (int i = 0; i < 256; i += 2) {
            a = encrypt(a);
            ChangedSBox1[i] = trim(a >>> 32);
            ChangedSBox1[i + 1] = trim(a);
        }

        for (int i = 0; i < 256; i += 2) {
            a = encrypt(a);
            ChangedSBox2[i] = trim(a >>> 32);
            ChangedSBox2[i + 1] = trim(a);
        }

        for (int i = 0; i < 256; i += 2) {
            a = encrypt(a);
            ChangedSBox3[i] = trim(a >>> 32);
            ChangedSBox3[i + 1] = trim(a);
        }
    }

    private long encrypt(long plaintext) {
        long xL = trim(plaintext >>> 32);
        long xR = trim(plaintext);

        for (int i = 0; i < 18; i++) {
            xL = xL ^ ChangedPArray[i];
            xR = F(xL) ^ xR;
            xL = xL + xR;
            xR = xL - xR;
            xL = xL - xR;
        }
        xL = xL + xR;
        xR = xL - xR;
        xL = xL - xR;

        xR = xR ^ ChangedPArray[16];
        xL = xL ^ ChangedPArray[17];
        return (xL << 32) | xR;
    }

    private long F(long data) {
        long result;
        long copyData = data;

        long x4 = copyData & 0x00FF;
        copyData = copyData >> 8;

        long x3 = copyData & 0x00FF;
        copyData = copyData >> 8;

        long x2 = copyData & 0x00FF;
        copyData = copyData >> 8;

        long x1 = copyData & 0x00FF;

        result = ChangedSBox0[(int)x1] + ChangedSBox1[(int)x2];
        result = result ^ ChangedSBox2[(int)x3];
        result = result + ChangedSBox3[(int)x4];
        return result;
    }

    private long trim(long data) {
        return (data & 0xFFFFFFFFL);
    }

}