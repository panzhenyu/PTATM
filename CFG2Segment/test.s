
test:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   0x2f9a(%rip)        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmp *0x2f9b(%rip)        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmp *0x2fad(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    104b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001050 <exit@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp *0x2f75(%rip)        # 3fd0 <exit@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001060 <_start>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    %ebp,%ebp
    1066:	49 89 d1             	mov    %rdx,%r9
    1069:	5e                   	pop    %rsi
    106a:	48 89 e2             	mov    %rsp,%rdx
    106d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1071:	50                   	push   %rax
    1072:	54                   	push   %rsp
    1073:	45 31 c0             	xor    %r8d,%r8d
    1076:	31 c9                	xor    %ecx,%ecx
    1078:	48 8d 3d ca 00 00 00 	lea    0xca(%rip),%rdi        # 1149 <main>
    107f:	ff 15 53 2f 00 00    	call   *0x2f53(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1085:	f4                   	hlt    
    1086:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    108d:	00 00 00 

0000000000001090 <deregister_tm_clones>:
    1090:	48 8d 3d 79 2f 00 00 	lea    0x2f79(%rip),%rdi        # 4010 <__TMC_END__>
    1097:	48 8d 05 72 2f 00 00 	lea    0x2f72(%rip),%rax        # 4010 <__TMC_END__>
    109e:	48 39 f8             	cmp    %rdi,%rax
    10a1:	74 15                	je     10b8 <deregister_tm_clones+0x28>
    10a3:	48 8b 05 36 2f 00 00 	mov    0x2f36(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    10aa:	48 85 c0             	test   %rax,%rax
    10ad:	74 09                	je     10b8 <deregister_tm_clones+0x28>
    10af:	ff e0                	jmp    *%rax
    10b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10b8:	c3                   	ret    
    10b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010c0 <register_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    0x2f49(%rip),%rdi        # 4010 <__TMC_END__>
    10c7:	48 8d 35 42 2f 00 00 	lea    0x2f42(%rip),%rsi        # 4010 <__TMC_END__>
    10ce:	48 29 fe             	sub    %rdi,%rsi
    10d1:	48 89 f0             	mov    %rsi,%rax
    10d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10d8:	48 c1 f8 03          	sar    $0x3,%rax
    10dc:	48 01 c6             	add    %rax,%rsi
    10df:	48 d1 fe             	sar    %rsi
    10e2:	74 14                	je     10f8 <register_tm_clones+0x38>
    10e4:	48 8b 05 05 2f 00 00 	mov    0x2f05(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    10eb:	48 85 c0             	test   %rax,%rax
    10ee:	74 08                	je     10f8 <register_tm_clones+0x38>
    10f0:	ff e0                	jmp    *%rax
    10f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <__do_global_dtors_aux>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmpb   $0x0,0x2f05(%rip)        # 4010 <__TMC_END__>
    110b:	75 2b                	jne    1138 <__do_global_dtors_aux+0x38>
    110d:	55                   	push   %rbp
    110e:	48 83 3d e2 2e 00 00 	cmpq   $0x0,0x2ee2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1115:	00 
    1116:	48 89 e5             	mov    %rsp,%rbp
    1119:	74 0c                	je     1127 <__do_global_dtors_aux+0x27>
    111b:	48 8b 3d e6 2e 00 00 	mov    0x2ee6(%rip),%rdi        # 4008 <__dso_handle>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <deregister_tm_clones>
    112c:	c6 05 dd 2e 00 00 01 	movb   $0x1,0x2edd(%rip)        # 4010 <__TMC_END__>
    1133:	5d                   	pop    %rbp
    1134:	c3                   	ret    
    1135:	0f 1f 00             	nopl   (%rax)
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <frame_dummy>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmp    10c0 <register_tm_clones>

0000000000001149 <main>:
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   %rbp
    114e:	48 89 e5             	mov    %rsp,%rbp
    1151:	48 83 ec 60          	sub    $0x60,%rsp
    1155:	c7 45 a8 01 00 00 00 	movl   $0x1,-0x58(%rbp)
    115c:	c7 45 ac 02 00 00 00 	movl   $0x2,-0x54(%rbp)
    1163:	83 7d a8 00          	cmpl   $0x0,-0x58(%rbp)
    1167:	74 06                	je     116f <main+0x26>
    1169:	83 45 ac 01          	addl   $0x1,-0x54(%rbp)
    116d:	eb 06                	jmp    1175 <main+0x2c>
    116f:	8b 45 a8             	mov    -0x58(%rbp),%eax
    1172:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1175:	c7 45 b0 00 00 00 00 	movl   $0x0,-0x50(%rbp)
    117c:	eb 10                	jmp    118e <main+0x45>
    117e:	8b 45 b0             	mov    -0x50(%rbp),%eax
    1181:	01 45 a8             	add    %eax,-0x58(%rbp)
    1184:	8b 45 b0             	mov    -0x50(%rbp),%eax
    1187:	29 45 ac             	sub    %eax,-0x54(%rbp)
    118a:	83 45 b0 01          	addl   $0x1,-0x50(%rbp)
    118e:	83 7d b0 63          	cmpl   $0x63,-0x50(%rbp)
    1192:	7e ea                	jle    117e <main+0x35>
    1194:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1198:	79 08                	jns    11a2 <main+0x59>
    119a:	8b 45 ac             	mov    -0x54(%rbp),%eax
    119d:	01 45 a8             	add    %eax,-0x58(%rbp)
    11a0:	eb 06                	jmp    11a8 <main+0x5f>
    11a2:	8b 45 a8             	mov    -0x58(%rbp),%eax
    11a5:	01 45 ac             	add    %eax,-0x54(%rbp)
    11a8:	c7 45 b4 00 00 00 00 	movl   $0x0,-0x4c(%rbp)
    11af:	eb 10                	jmp    11c1 <main+0x78>
    11b1:	8b 45 b4             	mov    -0x4c(%rbp),%eax
    11b4:	01 45 a8             	add    %eax,-0x58(%rbp)
    11b7:	8b 45 b4             	mov    -0x4c(%rbp),%eax
    11ba:	29 45 ac             	sub    %eax,-0x54(%rbp)
    11bd:	83 45 b4 01          	addl   $0x1,-0x4c(%rbp)
    11c1:	83 7d b4 63          	cmpl   $0x63,-0x4c(%rbp)
    11c5:	7e ea                	jle    11b1 <main+0x68>
    11c7:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    11cb:	79 08                	jns    11d5 <main+0x8c>
    11cd:	8b 45 ac             	mov    -0x54(%rbp),%eax
    11d0:	01 45 a8             	add    %eax,-0x58(%rbp)
    11d3:	eb 06                	jmp    11db <main+0x92>
    11d5:	8b 45 a8             	mov    -0x58(%rbp),%eax
    11d8:	01 45 ac             	add    %eax,-0x54(%rbp)
    11db:	c7 45 b8 00 00 00 00 	movl   $0x0,-0x48(%rbp)
    11e2:	eb 10                	jmp    11f4 <main+0xab>
    11e4:	8b 45 b8             	mov    -0x48(%rbp),%eax
    11e7:	01 45 a8             	add    %eax,-0x58(%rbp)
    11ea:	8b 45 b8             	mov    -0x48(%rbp),%eax
    11ed:	29 45 ac             	sub    %eax,-0x54(%rbp)
    11f0:	83 45 b8 01          	addl   $0x1,-0x48(%rbp)
    11f4:	83 7d b8 63          	cmpl   $0x63,-0x48(%rbp)
    11f8:	7e ea                	jle    11e4 <main+0x9b>
    11fa:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    11fe:	79 08                	jns    1208 <main+0xbf>
    1200:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1203:	01 45 a8             	add    %eax,-0x58(%rbp)
    1206:	eb 06                	jmp    120e <main+0xc5>
    1208:	8b 45 a8             	mov    -0x58(%rbp),%eax
    120b:	01 45 ac             	add    %eax,-0x54(%rbp)
    120e:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
    1215:	eb 10                	jmp    1227 <main+0xde>
    1217:	8b 45 bc             	mov    -0x44(%rbp),%eax
    121a:	01 45 a8             	add    %eax,-0x58(%rbp)
    121d:	8b 45 bc             	mov    -0x44(%rbp),%eax
    1220:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1223:	83 45 bc 01          	addl   $0x1,-0x44(%rbp)
    1227:	83 7d bc 63          	cmpl   $0x63,-0x44(%rbp)
    122b:	7e ea                	jle    1217 <main+0xce>
    122d:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1231:	79 08                	jns    123b <main+0xf2>
    1233:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1236:	01 45 a8             	add    %eax,-0x58(%rbp)
    1239:	eb 06                	jmp    1241 <main+0xf8>
    123b:	8b 45 a8             	mov    -0x58(%rbp),%eax
    123e:	01 45 ac             	add    %eax,-0x54(%rbp)
    1241:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%rbp)
    1248:	eb 10                	jmp    125a <main+0x111>
    124a:	8b 45 c0             	mov    -0x40(%rbp),%eax
    124d:	01 45 a8             	add    %eax,-0x58(%rbp)
    1250:	8b 45 c0             	mov    -0x40(%rbp),%eax
    1253:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1256:	83 45 c0 01          	addl   $0x1,-0x40(%rbp)
    125a:	83 7d c0 63          	cmpl   $0x63,-0x40(%rbp)
    125e:	7e ea                	jle    124a <main+0x101>
    1260:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1264:	79 08                	jns    126e <main+0x125>
    1266:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1269:	01 45 a8             	add    %eax,-0x58(%rbp)
    126c:	eb 06                	jmp    1274 <main+0x12b>
    126e:	8b 45 a8             	mov    -0x58(%rbp),%eax
    1271:	01 45 ac             	add    %eax,-0x54(%rbp)
    1274:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
    127b:	eb 10                	jmp    128d <main+0x144>
    127d:	8b 45 c4             	mov    -0x3c(%rbp),%eax
    1280:	01 45 a8             	add    %eax,-0x58(%rbp)
    1283:	8b 45 c4             	mov    -0x3c(%rbp),%eax
    1286:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1289:	83 45 c4 01          	addl   $0x1,-0x3c(%rbp)
    128d:	83 7d c4 63          	cmpl   $0x63,-0x3c(%rbp)
    1291:	7e ea                	jle    127d <main+0x134>
    1293:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1297:	79 08                	jns    12a1 <main+0x158>
    1299:	8b 45 ac             	mov    -0x54(%rbp),%eax
    129c:	01 45 a8             	add    %eax,-0x58(%rbp)
    129f:	eb 06                	jmp    12a7 <main+0x15e>
    12a1:	8b 45 a8             	mov    -0x58(%rbp),%eax
    12a4:	01 45 ac             	add    %eax,-0x54(%rbp)
    12a7:	c7 45 c8 00 00 00 00 	movl   $0x0,-0x38(%rbp)
    12ae:	eb 10                	jmp    12c0 <main+0x177>
    12b0:	8b 45 c8             	mov    -0x38(%rbp),%eax
    12b3:	01 45 a8             	add    %eax,-0x58(%rbp)
    12b6:	8b 45 c8             	mov    -0x38(%rbp),%eax
    12b9:	29 45 ac             	sub    %eax,-0x54(%rbp)
    12bc:	83 45 c8 01          	addl   $0x1,-0x38(%rbp)
    12c0:	83 7d c8 63          	cmpl   $0x63,-0x38(%rbp)
    12c4:	7e ea                	jle    12b0 <main+0x167>
    12c6:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    12ca:	79 08                	jns    12d4 <main+0x18b>
    12cc:	8b 45 ac             	mov    -0x54(%rbp),%eax
    12cf:	01 45 a8             	add    %eax,-0x58(%rbp)
    12d2:	eb 06                	jmp    12da <main+0x191>
    12d4:	8b 45 a8             	mov    -0x58(%rbp),%eax
    12d7:	01 45 ac             	add    %eax,-0x54(%rbp)
    12da:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    12e1:	eb 10                	jmp    12f3 <main+0x1aa>
    12e3:	8b 45 cc             	mov    -0x34(%rbp),%eax
    12e6:	01 45 a8             	add    %eax,-0x58(%rbp)
    12e9:	8b 45 cc             	mov    -0x34(%rbp),%eax
    12ec:	29 45 ac             	sub    %eax,-0x54(%rbp)
    12ef:	83 45 cc 01          	addl   $0x1,-0x34(%rbp)
    12f3:	83 7d cc 63          	cmpl   $0x63,-0x34(%rbp)
    12f7:	7e ea                	jle    12e3 <main+0x19a>
    12f9:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    12fd:	79 08                	jns    1307 <main+0x1be>
    12ff:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1302:	01 45 a8             	add    %eax,-0x58(%rbp)
    1305:	eb 06                	jmp    130d <main+0x1c4>
    1307:	8b 45 a8             	mov    -0x58(%rbp),%eax
    130a:	01 45 ac             	add    %eax,-0x54(%rbp)
    130d:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    1314:	eb 10                	jmp    1326 <main+0x1dd>
    1316:	8b 45 d0             	mov    -0x30(%rbp),%eax
    1319:	01 45 a8             	add    %eax,-0x58(%rbp)
    131c:	8b 45 d0             	mov    -0x30(%rbp),%eax
    131f:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1322:	83 45 d0 01          	addl   $0x1,-0x30(%rbp)
    1326:	83 7d d0 63          	cmpl   $0x63,-0x30(%rbp)
    132a:	7e ea                	jle    1316 <main+0x1cd>
    132c:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1330:	79 08                	jns    133a <main+0x1f1>
    1332:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1335:	01 45 a8             	add    %eax,-0x58(%rbp)
    1338:	eb 06                	jmp    1340 <main+0x1f7>
    133a:	8b 45 a8             	mov    -0x58(%rbp),%eax
    133d:	01 45 ac             	add    %eax,-0x54(%rbp)
    1340:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    1347:	eb 10                	jmp    1359 <main+0x210>
    1349:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    134c:	01 45 a8             	add    %eax,-0x58(%rbp)
    134f:	8b 45 d4             	mov    -0x2c(%rbp),%eax
    1352:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1355:	83 45 d4 01          	addl   $0x1,-0x2c(%rbp)
    1359:	83 7d d4 63          	cmpl   $0x63,-0x2c(%rbp)
    135d:	7e ea                	jle    1349 <main+0x200>
    135f:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1363:	79 08                	jns    136d <main+0x224>
    1365:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1368:	01 45 a8             	add    %eax,-0x58(%rbp)
    136b:	eb 06                	jmp    1373 <main+0x22a>
    136d:	8b 45 a8             	mov    -0x58(%rbp),%eax
    1370:	01 45 ac             	add    %eax,-0x54(%rbp)
    1373:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%rbp)
    137a:	eb 10                	jmp    138c <main+0x243>
    137c:	8b 45 d8             	mov    -0x28(%rbp),%eax
    137f:	01 45 a8             	add    %eax,-0x58(%rbp)
    1382:	8b 45 d8             	mov    -0x28(%rbp),%eax
    1385:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1388:	83 45 d8 01          	addl   $0x1,-0x28(%rbp)
    138c:	83 7d d8 63          	cmpl   $0x63,-0x28(%rbp)
    1390:	7e ea                	jle    137c <main+0x233>
    1392:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1396:	79 08                	jns    13a0 <main+0x257>
    1398:	8b 45 ac             	mov    -0x54(%rbp),%eax
    139b:	01 45 a8             	add    %eax,-0x58(%rbp)
    139e:	eb 06                	jmp    13a6 <main+0x25d>
    13a0:	8b 45 a8             	mov    -0x58(%rbp),%eax
    13a3:	01 45 ac             	add    %eax,-0x54(%rbp)
    13a6:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
    13ad:	eb 10                	jmp    13bf <main+0x276>
    13af:	8b 45 dc             	mov    -0x24(%rbp),%eax
    13b2:	01 45 a8             	add    %eax,-0x58(%rbp)
    13b5:	8b 45 dc             	mov    -0x24(%rbp),%eax
    13b8:	29 45 ac             	sub    %eax,-0x54(%rbp)
    13bb:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
    13bf:	83 7d dc 63          	cmpl   $0x63,-0x24(%rbp)
    13c3:	7e ea                	jle    13af <main+0x266>
    13c5:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    13c9:	79 08                	jns    13d3 <main+0x28a>
    13cb:	8b 45 ac             	mov    -0x54(%rbp),%eax
    13ce:	01 45 a8             	add    %eax,-0x58(%rbp)
    13d1:	eb 06                	jmp    13d9 <main+0x290>
    13d3:	8b 45 a8             	mov    -0x58(%rbp),%eax
    13d6:	01 45 ac             	add    %eax,-0x54(%rbp)
    13d9:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    13e0:	eb 10                	jmp    13f2 <main+0x2a9>
    13e2:	8b 45 e0             	mov    -0x20(%rbp),%eax
    13e5:	01 45 a8             	add    %eax,-0x58(%rbp)
    13e8:	8b 45 e0             	mov    -0x20(%rbp),%eax
    13eb:	29 45 ac             	sub    %eax,-0x54(%rbp)
    13ee:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    13f2:	83 7d e0 63          	cmpl   $0x63,-0x20(%rbp)
    13f6:	7e ea                	jle    13e2 <main+0x299>
    13f8:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    13fc:	79 08                	jns    1406 <main+0x2bd>
    13fe:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1401:	01 45 a8             	add    %eax,-0x58(%rbp)
    1404:	eb 06                	jmp    140c <main+0x2c3>
    1406:	8b 45 a8             	mov    -0x58(%rbp),%eax
    1409:	01 45 ac             	add    %eax,-0x54(%rbp)
    140c:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    1413:	eb 10                	jmp    1425 <main+0x2dc>
    1415:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    1418:	01 45 a8             	add    %eax,-0x58(%rbp)
    141b:	8b 45 e4             	mov    -0x1c(%rbp),%eax
    141e:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1421:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    1425:	83 7d e4 63          	cmpl   $0x63,-0x1c(%rbp)
    1429:	7e ea                	jle    1415 <main+0x2cc>
    142b:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    142f:	79 08                	jns    1439 <main+0x2f0>
    1431:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1434:	01 45 a8             	add    %eax,-0x58(%rbp)
    1437:	eb 06                	jmp    143f <main+0x2f6>
    1439:	8b 45 a8             	mov    -0x58(%rbp),%eax
    143c:	01 45 ac             	add    %eax,-0x54(%rbp)
    143f:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    1446:	eb 10                	jmp    1458 <main+0x30f>
    1448:	8b 45 e8             	mov    -0x18(%rbp),%eax
    144b:	01 45 a8             	add    %eax,-0x58(%rbp)
    144e:	8b 45 e8             	mov    -0x18(%rbp),%eax
    1451:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1454:	83 45 e8 01          	addl   $0x1,-0x18(%rbp)
    1458:	83 7d e8 63          	cmpl   $0x63,-0x18(%rbp)
    145c:	7e ea                	jle    1448 <main+0x2ff>
    145e:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1462:	79 08                	jns    146c <main+0x323>
    1464:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1467:	01 45 a8             	add    %eax,-0x58(%rbp)
    146a:	eb 06                	jmp    1472 <main+0x329>
    146c:	8b 45 a8             	mov    -0x58(%rbp),%eax
    146f:	01 45 ac             	add    %eax,-0x54(%rbp)
    1472:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    1479:	eb 10                	jmp    148b <main+0x342>
    147b:	8b 45 ec             	mov    -0x14(%rbp),%eax
    147e:	01 45 a8             	add    %eax,-0x58(%rbp)
    1481:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1484:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1487:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    148b:	83 7d ec 63          	cmpl   $0x63,-0x14(%rbp)
    148f:	7e ea                	jle    147b <main+0x332>
    1491:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1495:	79 08                	jns    149f <main+0x356>
    1497:	8b 45 ac             	mov    -0x54(%rbp),%eax
    149a:	01 45 a8             	add    %eax,-0x58(%rbp)
    149d:	eb 06                	jmp    14a5 <main+0x35c>
    149f:	8b 45 a8             	mov    -0x58(%rbp),%eax
    14a2:	01 45 ac             	add    %eax,-0x54(%rbp)
    14a5:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    14ac:	eb 10                	jmp    14be <main+0x375>
    14ae:	8b 45 f0             	mov    -0x10(%rbp),%eax
    14b1:	01 45 a8             	add    %eax,-0x58(%rbp)
    14b4:	8b 45 f0             	mov    -0x10(%rbp),%eax
    14b7:	29 45 ac             	sub    %eax,-0x54(%rbp)
    14ba:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
    14be:	83 7d f0 63          	cmpl   $0x63,-0x10(%rbp)
    14c2:	7e ea                	jle    14ae <main+0x365>
    14c4:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    14c8:	79 08                	jns    14d2 <main+0x389>
    14ca:	8b 45 ac             	mov    -0x54(%rbp),%eax
    14cd:	01 45 a8             	add    %eax,-0x58(%rbp)
    14d0:	eb 06                	jmp    14d8 <main+0x38f>
    14d2:	8b 45 a8             	mov    -0x58(%rbp),%eax
    14d5:	01 45 ac             	add    %eax,-0x54(%rbp)
    14d8:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    14df:	eb 10                	jmp    14f1 <main+0x3a8>
    14e1:	8b 45 f4             	mov    -0xc(%rbp),%eax
    14e4:	01 45 a8             	add    %eax,-0x58(%rbp)
    14e7:	8b 45 f4             	mov    -0xc(%rbp),%eax
    14ea:	29 45 ac             	sub    %eax,-0x54(%rbp)
    14ed:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
    14f1:	83 7d f4 63          	cmpl   $0x63,-0xc(%rbp)
    14f5:	7e ea                	jle    14e1 <main+0x398>
    14f7:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    14fb:	79 08                	jns    1505 <main+0x3bc>
    14fd:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1500:	01 45 a8             	add    %eax,-0x58(%rbp)
    1503:	eb 06                	jmp    150b <main+0x3c2>
    1505:	8b 45 a8             	mov    -0x58(%rbp),%eax
    1508:	01 45 ac             	add    %eax,-0x54(%rbp)
    150b:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    1512:	eb 10                	jmp    1524 <main+0x3db>
    1514:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1517:	01 45 a8             	add    %eax,-0x58(%rbp)
    151a:	8b 45 f8             	mov    -0x8(%rbp),%eax
    151d:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1520:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    1524:	83 7d f8 63          	cmpl   $0x63,-0x8(%rbp)
    1528:	7e ea                	jle    1514 <main+0x3cb>
    152a:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    152e:	79 08                	jns    1538 <main+0x3ef>
    1530:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1533:	01 45 a8             	add    %eax,-0x58(%rbp)
    1536:	eb 06                	jmp    153e <main+0x3f5>
    1538:	8b 45 a8             	mov    -0x58(%rbp),%eax
    153b:	01 45 ac             	add    %eax,-0x54(%rbp)
    153e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1545:	eb 10                	jmp    1557 <main+0x40e>
    1547:	8b 45 fc             	mov    -0x4(%rbp),%eax
    154a:	01 45 a8             	add    %eax,-0x58(%rbp)
    154d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1550:	29 45 ac             	sub    %eax,-0x54(%rbp)
    1553:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1557:	83 7d fc 63          	cmpl   $0x63,-0x4(%rbp)
    155b:	7e ea                	jle    1547 <main+0x3fe>
    155d:	83 7d ac 00          	cmpl   $0x0,-0x54(%rbp)
    1561:	79 08                	jns    156b <main+0x422>
    1563:	8b 45 ac             	mov    -0x54(%rbp),%eax
    1566:	01 45 a8             	add    %eax,-0x58(%rbp)
    1569:	eb 06                	jmp    1571 <main+0x428>
    156b:	8b 45 a8             	mov    -0x58(%rbp),%eax
    156e:	01 45 ac             	add    %eax,-0x54(%rbp)
    1571:	bf 00 00 00 00       	mov    $0x0,%edi
    1576:	e8 d5 fa ff ff       	call   1050 <exit@plt>

Disassembly of section .fini:

000000000000157c <_fini>:
    157c:	f3 0f 1e fa          	endbr64 
    1580:	48 83 ec 08          	sub    $0x8,%rsp
    1584:	48 83 c4 08          	add    $0x8,%rsp
    1588:	c3                   	ret    
