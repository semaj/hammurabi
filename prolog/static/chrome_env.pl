:- module(chrome_env, [
     trusted/1,
     symantecRoot/1,
     symantecException/1,
     symantecManagedCA/1,
     crlSet/1
]).


% Name constraints
anssiFingerprint("B9BEA7860A962EA3611DAB97AB6DA3E21C1068B97D55575ED0E11279C11C8932").
anssiDomain("*.fr"). %  France
anssiDomain("*.gp"). %  Guadeloupe
anssiDomain("*.gf"). %  Guyane
anssiDomain("*.mq"). %  Martinique
anssiDomain("*.re"). %  Réunion
anssiDomain("*.yt"). %  Mayotte
anssiDomain("*.pm"). %  Saint-Pierre et Miquelon
anssiDomain("*.bl"). %  Saint Barthélemy
anssiDomain("*.mf"). %  Saint Martin
anssiDomain("*.wf"). %  Wallis et Futuna
anssiDomain("*.pf"). %  Polynésie française
anssiDomain("*.nc"). %  Nouvelle Calédonie
anssiDomain("*.tf"). %  Terres australes et antarctiques françaises

indiaFingerprint("F375E2F77A108BACC4234894A9AF308EDECA1ACD8FBDE0E7AAA9634E9DAF7E1C").
indiaFingerprint("2D66A702AE81BA03AF8CFF55AB318AFA919039D9F31B4D64388680F81311B65A").
indiaFingerprint("60109BC6C38328598A112C7A25E38B0F23E5A7511CB815FB64E0C4FF05DB7DF7").

indiaDomain("*.gov.in").
indiaDomain("*.nic.in").
indiaDomain("*.ac.in").
indiaDomain("*.rbi.org.in").
indiaDomain("*.bankofindia.co.in").
indiaDomain("*.ncode.in").
indiaDomain("*.tcs.co.in").


% This is our own Ruby CA for frankencert testing.
trusted("806900450323811634B49508D427C5C5F7BEC6733DD369FB2F6B7A4EA228223A").

trusted("5A2FC03F0C83B090BBFA40604B0988446C7636183DF9846E17101A447FB8EFD6").
trusted("125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F").
trusted("BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3").
trusted("86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B").
trusted("9A6EC012E1A7DA9DBE34194D478AD7C0DB1822FB071DF12981496ED104384113").
trusted("55926084EC963A64B96E2ABE01CE0BA86A64FBFEBCC7AAB5AFC155B37FD76066").
trusted("0376AB1D54C5F9803CE4B2E201A0EE7EEF7B57B636E8A93C9B8D4860C96F5FA7").
trusted("0A81EC5A929777F145904AF38D5D509F66B5E2C58FCDB531058B0E17F3F0B41B").
trusted("70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A").
trusted("BD71FDF6DA97E4CF62D1647ADD2581B07D79ADF8397EB4ECBA9C5E8488821423").
trusted("F356BEA244B7A91EB35D53CA9AD7864ACE018E2D35D5F8F96DDF68A6F41AA474").
trusted("04048028BF1F2864D48F9AD4D83294366A828856553F3B14303F90147F5D40EF").
trusted("16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB").
trusted("9A114025197C5BB95D94E63D55CD43790847B646B23CDF11ADA4A00EFF15FB48").
trusted("EDF7EBBCA27A2A384D387B7D4010C666E2EDB4843E4C29B4AE1D5B9332E6B24D").
trusted("E23D4A036D7B70E9F595B1422079D2B91EDFBB1FB651A0633EAA8A9DC5F80703").
trusted("E3B6A2DB2ED7CE48842F7AC53241C7B71D54144BFB40C11F3F1D0B42F5EEA12D").
trusted("2A99F5BC1174B73CBB1D620884E01C34E51CCB3978DA125F0E33268883BF4158").
trusted("0F993C8AEF97BAAF5687140ED59AD1821BB4AFACF0AA9A58B5D57A338A3AFBCB").
trusted("EAA962C4FA4A6BAFEBE415196D351CCD888D4F53F3FA8AE6D7C466A94E6042BB").
trusted("5C58468D55F58E497E743982D2B50010B6D165374ACF83A7D4A32DB768C4408E").
trusted("5CC3D78E4E1D5E45547A04E6873E64F90CF9536D1CCC2EF800F355C4C5FD70FD").
trusted("063E4AFAC491DFD332F3089B8542E94617D893D7FE944E10A7937EE29D9693C0").
trusted("D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4").
trusted("0C2CD63DF7806FA399EDE809116B575BF87989F06518F9808C860503178BAF66").
trusted("1793927A0614549789ADCE2F8F34F7F0B66D0F3AE3A3B84D21EC15DBBA4FADC7").
trusted("52F0E1C4E58EC629291B60317F074671B85D7EA80D5B07273463534B32B40234").
trusted("960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3").
trusted("B6191A50D0C3977F7DA99BCDAAC86A227DAEB9679EC70BA3B0C9D92271C170D3").
trusted("3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C").
trusted("7D05EBB682339F8C9451EE094EEBFEFA7953A114EDB2F44949452FAB7D2FC185").
trusted("7E37CB8B4C47090CAB36551BA6F45DB840680FBA166A952DB100717F43053FC2").
trusted("4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161").
trusted("CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F").
trusted("31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0").
trusted("7431E5F4C3C1CE4690774F0B61E05440883BA9A01ED00BA6ABD7806ED3B118CF").
trusted("552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988").
trusted("0687260331A72403D909F105E69BCF0D32E1BD2493FFC6D9206D11BCD6770739").
trusted("49E7A442ACF0EA6287050054B52564B650E4F49E42E348D6AA38E039E957B1C1").
trusted("EEC5496B988CE98625B934092EEC2908BED0B0F316C2D4730C84EAF1F3D34881").
trusted("88497F01602F3154246AE28C4D5AEF10F1D87EBB76626F4AE0B7F95BA7968799").
trusted("3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76").
trusted("6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177").
trusted("73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C").
trusted("02ED0EB28C14DA45165C566791700D6451D7FB56F0B2AB1D3B8EB070E56EDFF5").
trusted("43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339").
trusted("C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5").
trusted("B0BFD52BB0D7D9BD92BF5D4DC13DA255C02C542F378365EA893911F55E55F23C").
trusted("FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A").
trusted("37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C").
trusted("5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766").
trusted("B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4").
trusted("A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B").
trusted("A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912").
trusted("136335439334A7698016A0D324DE72284E079D7B5220BB8FBD747816EEBEBACA").
trusted("BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C").
trusted("179FBC148A3DD00FD24EA13458CC43BFA7F59C8182D783A513F6EBEC100C8924").
trusted("EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99").
trusted("CA42DD41745FD0B81EB902362CF9D8BF719DA1BD1B1EFC946F5B4C99F42C1B9E").
trusted("CBB522D7B7F127AD6A0113865BDF1CD4102E7D0759AF635A7CF4720DC963C53B").
trusted("C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4").
trusted("45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA").
trusted("BC104F15A48BE709DCA542A7E1D4B9DF6F054527E802EAA92D595444258AFE71").
trusted("F9E67D336C51002AC054C632022D66DDA2E7E3FFF10AD061ED31D8BBB410CFB2").
trusted("5D56499BE4D2E08BCFCAD08A3E38723D50503BDE706948E42F55603019E528AE").
trusted("30D0895A9A448A262091635522D1F52010B5867ACAE12C78EF958FD4F4389F2F").
trusted("2530CC8E98321502BAD96F9B1FBA1B099E2D299E0F4548BB914F363BC0D4531F").
trusted("3C5F81FEA5FAB82C64BFA2EAECAFCDE8E077FC8620A7CAE537163DF36EDBF378").
trusted("6C61DAC3A2DEF031506BE036D2A6FE401994FBD13DF9C8D466599274C446EC98").
trusted("15F0BA00A3AC7AF3AC884C072B1011A077BD77C097F40164B2F8598ABD83860C").
trusted("41C923866AB4CAD6B7AD578081582E020797A6CBDF4FFF78CE8396B38937D7F5").
trusted("6B9C08E86EB0F767CFAD65CD98B62149E5494A67F5845E7BD1ED019F27B86BD6").
trusted("8A866FD1B276B57E578E921C65828A2BED58E9F2F288054134B7F1F4BFC9CC74").
trusted("85A0DD7DD720ADB7FF05F83D542B209DC7FF4528F7D677B18389FEA5E5C49E86").
trusted("8FE4FB0AF93A4D0D67DB0BEBB23E37C71BF325DCBCDD240EA04DAF58B47E1840").
trusted("18F1FC7F205DF8ADDDEB7FE007DD57E3AF375A9C4D8D73546BF4F1FED1E18D35").
trusted("88EF81DE202EB018452E43F864725CEA5FBD1FC2D9D205730709C5D8B8690F46").
trusted("A45EDE3BBBF09C8AE15C72EFC07268D693A21C996FD51E67CA079460FD6D8873").
trusted("4200F5043AC8590EBB527D209ED1503029FBCBD41CA1B506EC27F15ADE7DAC69").
trusted("BF0FEEFB9E3A581AD5F9E9DB7589985743D261085C4D314F6F5D7259AA421612").
trusted("F1C1B50AE5A20DD8030EC9F6BC24823DD367B5255759B4E71B61FCE9F7375D73").
trusted("513B2CECB810D4CDE5DD85391ADFC6C2DD60D87BB736D2B521484AA47A0EBEF6").
trusted("E75E72ED9F560EEC6EB4800073A43FC3AD19195A392282017895974A99026B6C").
trusted("7908B40314C138100B518D0735807FFBFCF8518A0095337105BA386B153DD927").
trusted("4D2491414CFE956746EC4CEFA6CF6F72E28A1329432F9D8A907AC4CB5DADC15A").
trusted("668C83947DA63B724BECE1743C31A0E6AED0DB8EC5B31BE377BB784F91B6716F").
trusted("3C4FB0B95AB8B30032F432B86F535FE172C185D0FD39865837CF36187FA6F428").
trusted("1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658").
trusted("2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5").
trusted("568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5").
trusted("62DD0BE9B9F50A163EA0F8E75C053B1ECA57EA55C8688F647C6881F2C8357B95").
trusted("BE6C4DA2BBB9BA59B6F3939768374246C3C005993FA98F020D1DEDBED48A81D5").
trusted("7600295EEFE85B9E1FD624DB76062AAAAE59818A54D2774CD4C0B2C01131E1B3").
trusted("DD6936FE21F8F077C123A1A521C12224F72255B73E03A7260693E8A24B0FA389").
trusted("8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F").
trusted("A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557").
trusted("4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C").
trusted("C1B48299ABA5208FE9630ACE55CA68A03EDA5A519C8802A0D3A673BE8F8E557D").
trusted("91E2F5788D5810EBA7BA58737DE1548A8ECACD014598BC0B143E041B17052552").
trusted("FD73DAD31C644FF1B43BEF0CCDDA96710B9CD9875ECA7E31707AF3E96D522BBD").
trusted("59769007F7685D0FCD50872F9F95D5755A5B2B457D81F3692B610A98672F0E1B").
trusted("BFD88FE1101C41AE3E801BF8BE56350EE9BAD1A6B9BD515EDC5C6D5B8711AC44").
trusted("4FF460D54B9C86DABFBCFC5712E0400D2BED3FBC4D4FBDAA86E06ADCD2A9AD7A").
trusted("E793C9B02FD8AA13E21C31228ACCB08119643B749C898964B1746D46C3D4CBD2").
trusted("EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244").
trusted("69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79").
trusted("9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF").
trusted("2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C").
trusted("CECDDC905099D8DADFC5B1D209B737CBE2C18CFB2C10C0FF0BCF0D3286FC1AA2").
trusted("EBC5570C29018C4D67B1AA127BAF12F703B4611EBC17B7DAB5573894179B93FA").
trusted("8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E").
trusted("1BA5B2AA8C65401A82960118F80BEC4F62304D83CEC4713A19C39C011EA46DB4").
trusted("18CE6CFE7BF14E60B2E347B8DFE868CB31D02EBB3ADA271569F50343B46DB3A4").
trusted("E35D28419ED02025CFA69038CD623962458DA5C695FBDEA3C22B0BFB25897092").
trusted("B676F2EDDAE8775CD36CB0F63CD1D4603961F49E6265BA013A2F0307B6D0B804").
trusted("44B545AA8A25E65A73CA15DC27FC36D24C1CB9953A066539B11582DC487B4833").
trusted("A040929A02CE53B4ACF4F2FFC6981CE4496F755E6D45FE0B2A692BCD52523F36").
trusted("96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6").
trusted("54455F7129C20B1447C418F997168F24C58FC5023BF5DA5BE2EB6E1DD8902ED5").
trusted("A1339D33281A0B56E557D3D32B1CE7F9367EB094BD5FA72A7E5004C8DED7CAFE").
trusted("46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716").
trusted("BFFF8FD04433487D6A8AA60C1A29767A9FC2BBB05E420F713A13B992891D3893").
trusted("22A2C1F7BDED704CC1E701B5F408C310880FE956B5DE2A4A44F99C873A25A7C8").
trusted("2E7BF16CC22485A7BBE2AA8696750761B0AE39BE3B2FE9D0CC6D4EF73491425C").
trusted("3417BB06CC6007DA1B961C920B8AB4CE3FAD820E4AA30B9ACBC4A74EBDCEBC65").
trusted("85666A562EE0BE5CE925C1D8890A6F76A87EC16D4D7D5F29EA7419CF20123B69").
trusted("5A885DB19C01D912C5759388938CAFBBDF031AB2D48E91EE15589B42971D039C").
trusted("D40E9C86CD8FE468C1776959F49EA774FA548684B6C406F3909261F4DCE2575C").
trusted("0753E940378C1BD5E3836E395DAEA5CB839E5046F1BD0EAE1951CF10FEC7C965").
trusted("2CABEAFE37D06CA22ABA7391C0033D25982952C453647349763A3AB5AD6CCF69").
trusted("8560F91C3624DABA9570B5FEA0DBE36FF11A8323BE9486854FB3F34A5571198D").

blocked("42187727BE39FAF667AEB92BF0CC4E268F6E2EAD2CEFBEC575BDC90430024F69").
blocked("60B35C92F6C7CF23AC6152A8965AFE1650B5E0A2A81A9EC2D6DAB254F288A04D").
blocked("2CFE71E0DD30BC746B30C5699E2025D9AA783C8774D24FE4DFE13C62254821DD").
blocked("F3BAE5E9C0ADBFBFB6DBF7E04E74BE6EAD3CA98A5604FFE591CEA86C241848EC").
blocked("A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305").
blocked("FDEDB5BDFCB67411513A61AEE5CB5B5D7C52AF06028EFC996CC1B05B1D6CEA2B").
blocked("A686FEE577C88AB664D0787ECDFFF035F4806F3DE418DC9E4D516324FFF02083").
blocked("9ED8F9B0E8E42A1656B8E1DD18F42BA42DC06FE52686173BA2FC70E756F207DC").
blocked("A27AA9792554C9DE20873DDB7E945EB0AC38F45E3DA79C628D0DFB643D9426B4").
blocked("B8686723E415534BC0DBD16326F9486F85B0B0799BF6639334E61DAAE67F36CD").
blocked("3946901F46B0071E90D78279E82FABABCA177231A704BE72C5B0E8918566EA66").
blocked("1685BA27FDF24CECE203FD829AC3FED5C85460ED0735B2D15751019E951540C0").
blocked("5BF3A3B793465F3767D7C7B4A03D80367C8957C498299C29B903F33FE340AF7A").
blocked("294F55EF3BD7244C6FF8A68AB797E9186EC27582751A791515E3292E48372D61").
blocked("6BF5533D0DDEAF023D58E401277C26442B1F1AF1A0F2DBBD9B2E3BA3A292FB23").
blocked("0D136E439F0AB6E97F3A02A540DA9F0641AA554E1D66EA51AE2920D51B2F7217").
blocked("8A1BD21661C60015065212CC98B1ABB50DFD14C872A208E66BAE890F25C448AF").
blocked("4FEE0163686ECBD65DB968E7494F55D84B25486D438E9DE558D629D28CD4D176").
blocked("71253459E5E64D1F9077A5C458999B67D7D9E70706AF680B045EB1D27B79E38F").
blocked("450F1B421BB05C8609854884559C323319619E8B06B001EA2DCBB74A23AA3BE2").
blocked("A6A2217C1D192FE71FCE87870167011C26E1A9B8582F5F08D8ECB9B3209F5FDB").
blocked("76A45A496031E4DD2D7ED23E8F6FF97DBDEA980BAAC8B0BA94D7EDB551348645").
blocked("4CBBF8256BC9888A8007B2F386940A2E394378B0D903CBB3863C5A6394B889CE").
blocked("372447C43185C38EDD2CE0E9C853F9AC1576DDD1704C2F54D96076C089CB4227").
blocked("E95B2DFB7D75FB14EAA1F3CA2EB0F89F0594F033A571D08F912AB0E7856880FE").
blocked("1F17F2CBB109F01C885C94D9E74A48625AE9659665D6D7E7BC5A10332976370F").
blocked("3E26492E20B52DE79E15766E6CB4251A1D566B0DBFB225AA7D08DDA1DCEBBF0A").
blocked("7ABD72A323C9D179C722564F4E27A51DD4AFD24006B38A40CE918B94960BCF18").
blocked("2740D956B1127B791AA1B3CC644A4DBEDBA76186A23638B95102351A834EA861").
blocked("2EE746858D3FEEA35CFD15AD8D0FA8CE26B7DCE34642ABF2E33FE13E709C1CF5").
blocked("B89E6FEFEBC03FA6E814432E656B186DD8B04093757C2732BDDEA75BAC2497B9").
blocked("77F3DBFD8067088DEF93D6FCEC5CE91B88400B753601FB68965E3EE4E5236DF1").
blocked("612490837F2E7B61B99E9425AA932D0F165C656BE8446BFBA732E99D81C49289").
blocked("264EE666720C8D3780463A97C078A7F36D3FC2EA104DEB5DE7E261A32F38F088").
blocked("77DECE8000964A74AEED685C0C9301F081A29B6F1803B14230DBD0BAC7A39CFC").
blocked("3D824DFB070091EC293DCEF46BE3CE5A5385CCF9679725F949EC0E84B9081490").
blocked("41A235AB60F0643E752A2DB4E914D68C0542167DE9CA28DF25FD79A693C29072").
blocked("C67D722C1495BE02CBF9EF1159F5CA4AA782DC832DC6AA60C9AA076A0AD1E69D").

% From chromium net/cert/symantec_certs.cc

% not allowed
symantecRoot("9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF").
%symantecRoot("FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A").

symantecRoot("023C81CCE8E7C64FA942D3C15048707D35D9BB5B87F4F544C5BF1BC5643AF2FA").
symantecRoot("0999BF900BD5C297865E21E1AADE6CF6BB3A94D11AE5EA798442A4E2F813241F").
symantecRoot("0BDD5ABE940CAAABE8B2BBA88348FB6F4AA4CC84436F880BECE66B48BDA913D8").
symantecRoot("16A9E012D32329F282B10BBF57C7C0B42AE80F6AC9542EB409BC1C2CDE50D322").
symantecRoot("17755A5C295F3D2D72E6F031A1F07F400C588B9E582B22F17EAE31A1590D1185").
symantecRoot("1906C6124DBB438578D00E066D5054C6C37F0FA6028C05545E0994EDDAEC8629").
symantecRoot("1916F3508EC3FAD795F8DC4BD316F9C6085A64DE3C4153AC6D62D5EA19515D39").
symantecRoot("1D75D0831B9E0885394D32C7A1BFDB3DBC1C28E2B0E8391FB135981DBC5BA936").
symantecRoot("22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303").
symantecRoot("25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058").
symantecRoot("26C18DC6EEA6F632F676BCEBA1D8C2B48352F29C2D5FCDA878E09DCB832DD6E5").
symantecRoot("2DC9470BE63EF4ACF1BD828609402BB7B87BD99638A643934E88682D1BE8C308").
symantecRoot("2DEE5171596AB8F3CD3C7635FEA8E6C3006AA9E31DB39D03A7480DDB2428A33E").
symantecRoot("3027A298FA57314DC0E3DD1019411B8F404C43C3F934CE3BDF856512C80AA15C").
symantecRoot("31512680233F5F2A1F29437F56D4988CF0AFC41CC6C5DA6275928E9C0BEADE27").
symantecRoot("43B3107D7342165D406CF975CD79B36ED1645048F05D7FF6EA0096E427B7DB84").
symantecRoot("463DBB9B0A26ED2616397B643125FBD29B66CF3A46FDB4384B209E78237A1AFF").
symantecRoot("479D130BF3FC61DC2F1D508D239A13276AE7B3C9841011A02C1402C7E677BD5F").
symantecRoot("4905466623AB4178BE92AC5CBD6584F7A1E17F27652D5A85AF89504EA239AAAA").
symantecRoot("495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE").
symantecRoot("4BA6031CA305B09E53BDE3705145481D0332B651FE30370DD5254CC4D2CB32F3").
symantecRoot("5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE").
symantecRoot("567B8211FD20D3D283EE0CD7CE0672CB9D99BC5B487A58C9D54EC67F77D4A8F5").
symantecRoot("5C4F285388F38336269A55C7C12C0B3CA73FEF2A5A4DF82B89141E841A6C4DE4").
symantecRoot("67DC4F32FA10E7D01A79A073AA0C9E0212EC2FFC3D779E0AA7F9C0F0E1C2C893").
symantecRoot("6B86DE96A658A56820A4F35D90DB6C3EFDD574CE94B909CB0D7FF17C3C189D83").
symantecRoot("7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903").
symantecRoot("781F1C3A6A42E3E915222DB4967702A2E577AEB017075FA3C159851FDDD0535E").
symantecRoot("7CAA03465124590C601E567E52148E952C0CFFE89000530FE0D95B6D50EAAE41").
symantecRoot("809F2BAAE35AFB4F36BD6476CE75C2001077901B6AF5C4DAB82E188C6B95C1A1").
symantecRoot("81A98FC788C35F557645A95224E50CD1DAC8FFB209DC1E5688AA29205F132218").
symantecRoot("860A7F19210D5EAD057A78532B80951453CB2907315F3BA7AA47B69897D70F3F").
symantecRoot("87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5").
symantecRoot("95735473BD67A3B95A8D5F90C5A21ACE1E0D7947320674D4AB847972B91544D2").
symantecRoot("967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872").
symantecRoot("9699225C5DE52E56CDD32DF2E96D1CFEA5AA3CA0BB52CD8933C23B5C27443820").
symantecRoot("9C6F6A123CBAA4EE34DBECEEE24C97D738878CB423F3C2273903424F5D1F6DD5").
symantecRoot("A6F1F9BF8A0A9DDC080FB49B1EFC3D1A1C2C32DC0E136A5B00C97316F2A3DC11").
symantecRoot("AB3876C3DA5DE0C9CF6736868EE5B88BF9BA1DFF9C9D72D2FE5A8D2F78302166").
symantecRoot("AB39A4B025955691A40269F353FA1D5CB94EAF6C7EA9808484BBBB62FD9F68F3").
symantecRoot("AB5CDB3356397356D6E691973C25B8618B65D76A90486EA7A8A5C17767F4673A").
symantecRoot("AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F").
symantecRoot("ACF65E1D62CB58A2BAFD6FFAB40FB88699C47397CF5CB483D42D69CAD34CD48B").
symantecRoot("AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258").
symantecRoot("B1124142A5A1A5A28819C735340EFF8C9E2F8168FEE3BA187F253BC1A392D7E2").
symantecRoot("B2DEF5362AD3FACD04BD29047A43844F767034EA4892F80E56BEE690243E2502").
symantecRoot("BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB").
symantecRoot("C07135F6B452398264A4776DBD0A6A307C60A36F967BD26321DCB817B5C0C481").
symantecRoot("CAB482CD3E820C5CE72AA3B6FDBE988BB8A4F0407ECAFD8C926E36824EAB92DD").
symantecRoot("D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7").
symantecRoot("D3A25DA80DB7BAB129A066AB41503DDDFFA02C768C0589F99FD71193E69916B6").
symantecRoot("D4AF6C0A482310BD7C54BB7AB121916F86C0C07CD52FCAC32D3844C26005115F").
symantecRoot("DA800B80B2A87D399E66FA19D72FDF49983B47D8CF322C7C79503A0C7E28FEAF").
symantecRoot("F15F1D323ED9CA98E9EA95B33EC5DDA47EA4C329F952C16F65AD419E64520476").
symantecRoot("F2E9365EA121DF5EEBD8DE2468FDC171DC0A9E46DADC1AB41D52790BA980A7C2").
symantecRoot("F53C22059817DD96F400651639D2F857E21070A59ABED9079400D9F695506900").
symantecRoot("F6B59C8E2789A1FD5D5B253742FEADC6925CB93EDC345E53166E12C52BA2A601").
symantecRoot("FF5680CD73A5703DA04817A075FD462506A73506C4B81A1583EF549478D26476").


% these are allowed
symantecException("56E98DEAC006A729AFA2ED79F9E419DF69F451242596D2AAF284C74A855E352E").
symantecException("7289C06DEDD16B71A7DCCA66578572E2E109B11D70AD04C2601B6743BC66D07B").
symantecException("8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26").
symantecException("B5CF82D47EF9823F9AA78F123186C52E8879EA84B0F822C91D83E04279B78FD5").
symantecException("B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97").
symantecException("C0554BDE87A075EC13A61F275983AE023957294B454CAF0A9724E3B21B7935BC").
symantecException("E24F8E8C2185DA2F5E88D4579E817C47BF6EAFBC8505F0F960FD5A0DF4473AD3").
symantecException("EC722969CB64200AB6638F68AC538E40ABAB5B19A6485661042A1061C4612776").
symantecException("FAE46000D8F7042558541E98ACF351279589F83B6D3001C18442E4403D111849").

% these are allowed
symantecManagedCA("7CAC9A0FF315387750BA8BAFDB1C2BC29B3F0BBA16362CA93A90F84DA2DF5F3E").
symantecManagedCA("AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE").


% CRL sets. Last updated 24 Aug 2020

crlSet("006CB226A772C7182D7772383E373F0F229E7DFE3444810A8D6E50905D20D661").
crlSet("026F0A8E207F05F1F172DB713DC22D0F43C8FF0D69724AA6FAC6A8393DF62508").
crlSet("03CB44B933D7E14551E52DDBFC335A4D57BF65A703667B57AC961DE31E3A106D").
crlSet("049432F226A2C54FF0FDB50BD59C0100FBD242C19FA64069531C373798BC784F").
crlSet("051CF9FA95E40E9B83EDAEDA6961F6168C7879C4660172479CDD51AB03CEA62B").
crlSet("07E854F26A7CBD389927AA041BFEF1B6CD21DD143818AD947DC655A9E587FE88").
crlSet("08B3A6335FCE5EF48F8F0E543986C07FD18A3B1226129F61864BBD5BDD1F1CC9").
crlSet("0B1EDD5F16124A9B948C6A469540EEF5824E4B22FE0F3A6CC7C1781D2A73A8B8").
crlSet("0C7ACAA710226720BBC940349EE2E6148652A89DBF406A232C895F6DC78EBB9A").
crlSet("0CEFA30C4603621AADCE0EFB22F16D8E2E86DA257188BEC048C3D057B13C6E13").
crlSet("0DC4F77C58851615880980F62CCBD500AC4CBA5F0926F07BC5F75A47B6887386").
crlSet("0DDB66CBA3DAFA98A36F57E0647AC406B46E8CDC1C1FDDB4FB9B9C3A11C6E325").
crlSet("10BA3485CA8BB6880AB9531A4063E4001555561C7F2E055165F49B2D74FC5F6B").
crlSet("1134FD81561A2818ECCFFFC2E440A0CEF9A40E2926C08299804D738B0A97F63D").
crlSet("116258D835845DEDBB7F2B2D4D56BED1C1D4986762EA281101ECB13939601436").
crlSet("1255CABE8152FA64DF942F7A47417E29F96C1CE11BF8C84ECBE2815CC1280810").
crlSet("149F2EE63B9A5E5803240A770DC991FC2E3445E62831C245A49BC4F1F738FF9C").
crlSet("1746D63DE90F202F7F9E4800243EC43DAC1D492601C3D06FDDF3467531F506B8").
crlSet("176A861DC6B05292EB14CDC16A4BEFD472CDB12BA16770235AFC0593F7EC5254").
crlSet("1A4B50727F6085D9626F9B6F6791C3469EDF87FDD120BABD4E78C7F246E1BD51").
crlSet("1A78742AD34833991481FEEED6BE710206B05888FB3DBA9C681326551C70A53B").
crlSet("1A7A3A1A68DD2361E3F3BB855F3B26FCD88B197D8DD4DE06CF1B362AC89EC13B").
crlSet("1AD937AF57AF941AECD211B77E6DD5A0CD7D75A1DEC4358FFFF38299E78CAF93").
crlSet("1C75AC70747E99745E30A0516710AFA8483AC03BFA1C06CFCCA37B3652EFAB87").
crlSet("1EA3C5E43ED66C2DA2983A42A4A79B1E906786CE9F1B58621419A00463A87D38").
crlSet("1F4224CEC84FC99CED881FF6FCFD3E21F8C519C547AA6A5DD3DE247302CE50D1").
crlSet("1FFA0959E9484719FD3E002E870BB77D37E1ADFED8BD296E7ED68A7C1C5C7363").
crlSet("2021917E98263945C859C43F1D73CB4139053C414FA03CA3BC7EE88614298F3B").
crlSet("22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303").
crlSet("234D8FFC7EF8023C818BF19F47894186D7B2E75643280D96F9F39965289DE15E").
crlSet("23F2EDFF3EDE90259A9E30F40AF8F912A5E5B3694E6938440341F6060E014FFA").
crlSet("2596904DC4D699AE20C2CEF4DCE47F285937D77464AC370746F52DEA76BA0C28").
crlSet("25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058").
crlSet("25D4913CF587097414D29D26F6C1B1942CD6D64EAF45D0FCF81526ADBA96D324").
crlSet("29E7FDDA489E46EE486EFD75ACC48F251932DC9DA1872B31753CD64719567AA5").
crlSet("2A8BED32AE680D2D187B9A7AFD171D83FD0B935EAF9E2C1B43E80278D2063E39").
crlSet("2BCEE858158CF5465FC9D76F0DFA312FEF25A4DCA8501DA9B46B67D1FBFA1B64").
crlSet("2FC5667A4B9A2678ED6AC6AD25465FCBF6094BFCD9504097C7A8FA47ADE5E888").
crlSet("3219B09114FF495A3EB6EB00C2EFEAB34002AE5F0A56C7679EA087A3FA037E4F").
crlSet("3329BFA13B6007AB5FC3713F0ACB289426E2FBC99CC5C110A914B139571600B6").
crlSet("3380709AF3B096BE3CC2A40548142C0A520028DB09E2CB77AE2206616AB6CBB4").
crlSet("348767CDAD3BDD28B2B8DD5351AEC30C68CEC5CD69D276DF3827DBC4F5806464").
crlSet("3499F93FD394523BFB1EC4C3AD4DFB310131FBE9EE5476BDE6295DE808D5DD8F").
crlSet("36ECC61FC7E5F1923D167E67DFDE34608549B34A63C7C6E60FFD5C1840381F5C").
crlSet("37837317BCDB1D42C5922DC24BC3CE8559D456F9C434EB3B7103BFFEF1AC5772").
crlSet("384B464714D464FF584CE1CF85EFA57ADA20F35C2122778C82B76FBC75C5E5B0").
crlSet("3A260FD9DC3A62299DCD7BFF74D9415DD3EDF840BA25F25BD31AE71D0B144AEA").
crlSet("3B0D73B4BE4A854ADC3E51D7EF9FA48AEFBB2CDD824D67BDC7D7D09A2ABC2D43").
crlSet("4001E969257575115D7106854466555CA4145FB390F95632E8DA957A3407D4B2").
crlSet("40FCFC28875DCCBFEBCBDF6CD7433312DA63C4EFCF3BD7B1B505C22020AE0274").
crlSet("4179EDD981EF747477B49626408AF43DAA2CA7AB7F9E082C1060F84096774348").
crlSet("495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE").
crlSet("4A49EDBD2F8F8230BD5592B313573FE1C172A45FA98011CC1EDDBB36ADE3FCE5").
crlSet("4E2FE7B57BFFD5BB2E3382487B3938E85F78EB195DBD4832A2B2598B98057450").
crlSet("4E4E373CB7AC45D8331CC08D248A8E99E251F2ED58C609BC8209E09E7A882DFC").
crlSet("4F7162B974491C98585EC28FE759AA00C330D0B465190A896CC4B616231831FC").
crlSet("50CC86BA96DB3263C79A43EAD07553D9F56659E6907E72D8C026637A1CDC85DC").
crlSet("510D20E5C47F63CF666B20F61AF62BC099A42AC824FFA443A2DA7C90B1808A91").
crlSet("5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE").
crlSet("53F97DA3E2E0D8D3A007EECC2C95336736D5AEA6AD23F962908138E0289A87A3").
crlSet("55F77DE41C03792428F8D518C55104225BE43A5598D926A528AD653E1CCEC7BF").
crlSet("56174D3AD971A8944964B189811F3008493A6A90422E3C5804EC838D4F94F622").
crlSet("563B3CAF8CFEF34C2335CAF560A7A95906E8488462EB75AC59784830DF9E5B2B").
crlSet("56DC6C39B963E6ADB0E9E6131B5786916F65043EC02E4A1E1A9C73C50781DFA6").
crlSet("57E8B2FAD01E317F650DE76C8A224BFFC759C4FCFE78BD6CD7D439A14D5DD558").
crlSet("58DD61FEB36EA7D258724371709149CB121337864CACB2D0999AD20739D06477").
crlSet("5955AE291574A931342CF7450E16652EDE1E0FB3097E1571DFAC11C915601564").
crlSet("5A804CCFF6C860C72D48F6796618DEFFF7A2935DD3781C8748AE335D8604B004").
crlSet("5A889647220E54D6BD8A16817224520BB5C78E58984BD570506388B9DE0F075F").
crlSet("5AD75DDF06906F02697A488DAD99B070605CB9441FEEE98AD28EB0D1EFA84960").
crlSet("5B6B96F18CB18F6A62A9C7B9728E9E5587CD4E568D92F380F8AF6E224E21D319").
crlSet("5C41A73AB2C35DFCD771F6FD6E3E8FAC9B469D386CADDA56A95B646EB48CCA34").
crlSet("6106C0E3A0A299831875127BD7D3CC1859803D511CAC11EB6E0840DD166FC10E").
crlSet("616167201433AEA6C8E5E3070AFCAF6749188F814BD1ABB179AE8DAD3ABF26EC").
crlSet("6241005B14DECA4865543AABE8C6A46290185233571A069534708F263C3CC652").
crlSet("62554C17005543B237215F04268DCD2FD1C470240AD3C8660E25AE2C59630F55").
crlSet("63D9AF9B47B1064D49A10E7B7FD566DBC8CAA399459BFC2829C571AD8C6EF34A").
crlSet("682747F8BA621B87CDD3BC295ED5CABCE722A1C0C0363D1D68B38928D2787F1E").
crlSet("68897BF383723F09DE663559BA2E60504E773DA59C8717D7E0FEF16C77D6CADF").
crlSet("6A379372C3E96F12AF3198BFB709E278372B3184EAF3C862BC98409A5CBC0779").
crlSet("6B1A505E0246F2F60C490FF0C097A7BE27210CBB7500237F88B0CD48298BC9B8").
crlSet("6BCFC86C8DDC2AF2E6A1180A2DDABB37B7EA3755316B64B9B8951BF0CA351F06").
crlSet("6C464B9A5B233A5E874DA765C26F045010D2DDCFF45794F0B4C7E4AAFA501495").
crlSet("6D083573D455381897D30B39ED16F3AD07EA1DADE93757483F61EE31EBC17FD4").
crlSet("6D6F0C340971A218A31D10330EA9AE7C7A6550534C6EEFEDDD2118E114DB473E").
crlSet("6DBFAE00D37B9CD73F8FB47DE65917AF00E0DDDF42DBCEAC20C17C0275EE2095").
crlSet("7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903").
crlSet("702116CCD8BF23E16466F0E0DBA0ED6A239A9C1CD6A8F5A66B39AF3595020385").
crlSet("706BB1017C855C59169BAD5C1781CF597F12D2CAD2F63D1A4AA37493800FFB80").
crlSet("7662FD887DAA8DCEFD0FF74CFA9DC639230A36820187E0067E020682081DBCBF").
crlSet("76EE8590374C715437BBCA6BBA6028EADDE2DC6DBBB8C3F610E851F11D1AB7F5").
crlSet("77290717614B25F12964EBDB38B5F83CAADC0F6C36B0777F880FC6DEE1D339CC").
crlSet("797C92CC2B0158321F986174D5CC0326074076DF078FB0F8DBDAA02F668DFB35").
crlSet("7A768D45397AD44B29AEEB9C13BF08462EB6DA5A461A1BD4EE2B86173E53D80A").
crlSet("7AFE4B071A2F1F46F8BA944A26D584D5960B92FB48C3BA1B7CAB84905F32AACD").
crlSet("7CD67C248F69D83FC2F9BB01DCB1F7AD67A363D046043796D0984C3A231F6BB0").
crlSet("7E0EAD76BB6819DC2F54511A84354F6E8B307B9DD82058EA6C004F01D9DDA5DF").
crlSet("7E8782C150CE3952F802E636023A5D3E95BB5D68E33E85ADB2BA178125CEBF15").
crlSet("7F1D907A368940C73379B8CB7286C71EF3816C1A62AFD5F1417A4748731A4E94").
crlSet("7F1DEC8B0319548A056DE5BB521BD93EB74E6A76F28DFFB75B45A53B775AF7AB").
crlSet("82B5F84DAF47A59C7AB521E4982AEFA40A53406A3AEC26039EFA6B2E0E7244C1").
crlSet("84AAC093E08C49DBFFF8E560759248DBE67135B372B23D2A881D5F99CBB191E8").
crlSet("85D26BE90D934FCCDB4FF7B38D8C79CA7652B816D6A52446CA8428A6B85DC57C").
crlSet("86A68F050034126A540D39DB2C5F917EF66A94FB9619FA1ECD827CEA46BA0CB0").
crlSet("871A9194F4EED5B312FF40C84C1D524AED2F778BBFF25F138CF81F680A7ADC67").
crlSet("87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5").
crlSet("89DB8DCC534AA70619DEC7BF5D5FA15DC6D4A2794BC34F503DAE80614C29BB83").
crlSet("8A27B5557B4BEC7CC0305FBF3D53D1F71CD3F34910C5D65E27ECDDB82077BA3D").
crlSet("8A2AFFBD1A1C5D1BDCCBB7F548BA995F966806B3FD0C3A00FAE2E52F3C853989").
crlSet("8A903B600A080B38DFE20DFB6ACD23122F64620E5808B9FC8688952FC1A3559C").
crlSet("8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26").
crlSet("8C46A4188D63382F4CEEDD69EDBFDCA7B38EB85B76A2F469A20456AD157142DF").
crlSet("8D767764B3CBDA08929D072A22A561F4DCDD1BC57D3CBDDC948C47D2B47F9122").
crlSet("8E8046EC4CAC015A507CE0D2D0154A4B40E8E42B3165CFA546571435112D17E5").
crlSet("8E8B56F5918A25BD85DCE76663FD94CC23690F10EA9586613171C6F8378890D5").
crlSet("8FD112C3C8370F147D5CCD3A7D865EB8DD540783BAC69FC60088E3743FF33378").
crlSet("8FDE27B96D4C4FAF039A063BC966B90ADE2AB2F2260FF3D4EAA9A0B2FF00ECC4").
crlSet("918591F1E16D7BE0DB051967F7793DDDFFCFB9AB89D4CA35719DAF2231F0723B").
crlSet("927A1B8562280576D048C50321ADA43D8703D2D9521A18C28B8C46CC6AAE4EFD").
crlSet("92C46879626EF2CC1ECEA50C72FB5E385844095F21CBF3B283CB82E6B9FC6A58").
crlSet("9318226F8C83AFE47F5F47C24F59CE12DBA8C73B181BEE6B2EA1F40A06BC1869").
crlSet("94072AD3F58F70F93098E5A5F6C04C96C710BD849D83184919AE90EB890AE400").
crlSet("951EE046FA83316E6786C08C44F13B4CA2EAD2D2644D63314391C0CC70887D0D").
crlSet("952C2039C0243EB515DD73D83FC3643184874FEB0862A9837731ED9B4742E17A").
crlSet("9612500BB176AED81058869906DE333973B813D3FCD9BB1BE3BB848A323EA5C3").
crlSet("967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872").
crlSet("9736AC3B25D16C45A45418A964578156480A8CC434541DDC5DD59233229868DE").
crlSet("9847E5653E5E9E847516E5CB818606AA7544A19BE67FD7366D506988E8D84347").
crlSet("9CF4704F3EE5A59894B16BF00CFE73D588DAE269F51DE66A4BA77446EE2BD1F7").
crlSet("9E5A34B08929BC0A581C8936AAFD6AB7517BB15188B4F6FC02C45906F71595B0").
crlSet("A320F4D534D7BE97C1AE8DD0499735BC895C323ADD2D388BFCCF662C23D7F99A").
crlSet("A51A2F3A050E838A5050696578DBBEDAAC1A107EE2D9D48FAE505D18D0DA5CF8").
crlSet("A6E11FF15EC326A5E3F18AD33A056694DC84C699766D028A5AD0EFE1A8E53AC7").
crlSet("A72EAE212A827C0A3FD2F19DD1C744D4579B913D34A762539464931A5A45C894").
crlSet("A81293445DB196A2030F9E455FE3C74A9A4F8317B02B01406027A8708174434C").
crlSet("AA2630A7B617B04D0A294BAB7A8CAAA5016E6DBE604837A83A85719FAB667EB5").
crlSet("AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F").
crlSet("AC499048C7DD00C021B371E34AA7599EE6DE94076008ADAE0FABA298C83359E2").
crlSet("AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE").
crlSet("AE7F962CB9E6A7DBF7B833FB18FA9B71A89175DF949C232B6A9EF7CB3DF2BBFC").
crlSet("AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258").
crlSet("AF22737CDB0F52D6578A2D3DE912053396947270CC9318D0805E9512ECE77AE3").
crlSet("AFE67C4786A4C7EC6268847467CE478688C946778F15FABD9519EC7A32554727").
crlSet("B03D87B056D08CC9D4E675EF19CA83AB53532168A8258598BE72E6D85C7DD7C1").
crlSet("B21D2A743318712BA16F39919D961A4BAFBA3BCA9A43A75B1FCFE22C5D70CABA").
crlSet("B26B1A7CC7F59B56FEDCD37F8ECB25DD130A1D7A24F8610B59636D1BDBD91260").
crlSet("B489CCB224B9A6B81DD274CEAF5209C252998C9A76AF48E4F4C50A0728461825").
crlSet("B4D31633D83B3105CD26915F7C0E6BF8A0E38959A65EB6D83DD42F56D391A48E").
crlSet("B5EC35BAAB538884CFA8DD97376B102F03E53B482C64100C250722AE9B042CBC").
crlSet("B6FD04C1D307DE3CAEF051C509E2E9C5B3E69726A4A8932517DA4285BA1307DD").
crlSet("B70045B526AE7E6B9FBD4BAE7456CF1171903247C306262E1B533E0395BF1846").
crlSet("B89BCBB8ACD474C1BEA7DAD65037F48DCECC9DFAA0612C3C2445956419DF32FE").
crlSet("B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97").
crlSet("BACC592E8B8AD411B959FD808B740089DDAF06C165A0A7123947879588F97EFA").
crlSet("BB3DCDDE1BE98974119A5EBAC4BF3C5D85D5C5A3AB349D7FBAE9B94152FD4579").
crlSet("BB4128EC9620F2D2A49CE8E2C4E257AEBAD93A0F11C56B5FA4B00E23759FA39D").
crlSet("BB52086D0639E8DB332775AC8F4E8435D92CEB00F4E24F28FC0EABE240772E80").
crlSet("BB5685059377E908AAB9A3B07A0AC76214C29A074B4FCEBE21DC36671FBDB420").
crlSet("BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB").
crlSet("BE3DB7B79BFE579DCF9B07CA4CAD75AFF16975568E5B45CFCAE4D61FB63175A8").
crlSet("BFE82909872E4434F115C51A56168019594D0E03DCA363D9F3B4839D0BABCDE5").
crlSet("C16C0FAF9985FE65A0A491119C8E508E4DC5AA9BEB08194CB2BB7CEFD6B9D053").
crlSet("C2B3C31A4A29850AA8F3CF472A1169FF71B416579F6A4482EC7744B83DF988AC").
crlSet("C63D68C648A18B77641C427A669D61C9768A55F4FCD0322EAC96C57700299CF1").
crlSet("C784333D20BCD742B9FDC3236F4E509B8937070E73067E254DD3BF9C45BF4DDE").
crlSet("C7F43B4CF5B71568294F822B53762605F6DDD15CADECE739E9E2C3CBA61E9D67").
crlSet("C84005B7024EAF3D3E8451FBE9231F02047D28DC13F01676638097377B9A6811").
crlSet("CB6E91711AD6D55C8906F379CB071FB5C47933654A7415612EEE6629F26FBCD7").
crlSet("CE24EB0626DEFD8168C96A7701F09301600FE5DD0DBCE58E9C97B830AF02EF28").
crlSet("CEA8A2C66A03230FC998C2022E9B5DC4550B3D33E15612DB516D6ED5938F61CA").
crlSet("CED43902AB5FB57B442322DC0E172A4FB55F7178B808F94E780A6FD6CC6BD818").
crlSet("CF0B474ACE8469FABA402F02EEBDF9E1700D9CBE8BE4E4348407B69DD3196E94").
crlSet("D1C45377EBDCD618CD1651DC2E02C21D751E5AA9FCD1B3431FF6ECF6A31348FA").
crlSet("D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7").
crlSet("DD5ED1C090F9F448061BAA94A6BB11017544E9EEFAA20CC714CE6C633F5DC629").
crlSet("E04A022CE32F4CCF2C7F6046287B828A32A909F5E751447F83FD2C71F6FD8173").
crlSet("E5CA37BC7B6C361979BC6B123CA9A1DB019046D7FF5F57DFB854B19D10B0682F").
crlSet("E63BAD30738064605B71361B9755F5438775E34BD789ABC4901E9E772BC2B923").
crlSet("E69D11239A7ADFDB53A8DA4BD0E05A20EA0FDA98B5DB78099F993B8A8EB7C13E").
crlSet("E768343DED4537E5FC91E85736C8B4835B45E320BDC7B9623A76E3DFB9AEE1A3").
crlSet("EA87F462DEEFFFBD7775AA2A4B7E0FCB91C22EEE6DF69ED90100CCC73B311476").
crlSet("EAAD41CECA70BF6A222D160EA4A9AA757E1A56AEB395A22DD2A8A9BAF74BE1BE").
crlSet("F19A47AC01B579021066739E627FA9F44EEDAAAFF27357E269269E291D416362").
crlSet("F1C6BA670CFC88E4DF52973CAE420F0A089DD474144FE5806C420064E1591229").
crlSet("F2BA87A14A428ED667214F44AB0B33F0867025C24C8E0E7DDE6C0904F1B7D832").
crlSet("F3438E23B3CE532522FACF307923F58FD18608E9BA7ADDC30E952B43C49616C3").
crlSet("F463C54D9F1A047AED52656AC785E07EBEC528E0207BFD3F55D893237668F6AE").
crlSet("F48BADD7DF6A06690D0AE31373B12855F8DEDB14517F362A313101CC98CC6B35").
crlSet("FA1B0F9AC7627B9BA86AFD1563A3DADD7E94DDF8115B0E70A83A3E227EA43A5A").
crlSet("FB58E7F2D17FC366957E93F9F2939F73FE7D09E708865BCDA290DF733FEDC8E3").
crlSet("FDE8999A5E427319835C89A17D64A2DCD13A851C0916C4C547B6D8F7A6437D94").
crlSet("FEA2B7D645FBA73D753C1EC9A7870C40E1F7B0C561E927B985BF711866E36F22").
