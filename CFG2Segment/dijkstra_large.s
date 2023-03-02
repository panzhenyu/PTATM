
/home/pzy/project/mibench/network/dijkstra/dijkstra_large:     file format elf64-x86-64


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
    1020:	ff 35 52 2f 00 00    	push   0x2f52(%rip)        # 3f78 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 53 2f 00 00 	bnd jmp *0x2f53(%rip)        # 3f80 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   $0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	push   $0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	push   $0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	push   $0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmp 1020 <_init+0x20>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	push   $0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmp 1020 <_init+0x20>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	push   $0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	push   $0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	push   $0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10cf:	90                   	nop

Disassembly of section .plt.got:

00000000000010d0 <__cxa_finalize@plt>:
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	f2 ff 25 1d 2f 00 00 	bnd jmp *0x2f1d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

00000000000010e0 <free@plt>:
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	f2 ff 25 9d 2e 00 00 	bnd jmp *0x2e9d(%rip)        # 3f88 <free@GLIBC_2.2.5>
    10eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010f0 <putchar@plt>:
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	f2 ff 25 95 2e 00 00 	bnd jmp *0x2e95(%rip)        # 3f90 <putchar@GLIBC_2.2.5>
    10fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001100 <__isoc99_fscanf@plt>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	f2 ff 25 8d 2e 00 00 	bnd jmp *0x2e8d(%rip)        # 3f98 <__isoc99_fscanf@GLIBC_2.7>
    110b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001110 <puts@plt>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	f2 ff 25 85 2e 00 00 	bnd jmp *0x2e85(%rip)        # 3fa0 <puts@GLIBC_2.2.5>
    111b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001120 <printf@plt>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	f2 ff 25 7d 2e 00 00 	bnd jmp *0x2e7d(%rip)        # 3fa8 <printf@GLIBC_2.2.5>
    112b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001130 <malloc@plt>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	f2 ff 25 75 2e 00 00 	bnd jmp *0x2e75(%rip)        # 3fb0 <malloc@GLIBC_2.2.5>
    113b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001140 <fflush@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 6d 2e 00 00 	bnd jmp *0x2e6d(%rip)        # 3fb8 <fflush@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001150 <fopen@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 65 2e 00 00 	bnd jmp *0x2e65(%rip)        # 3fc0 <fopen@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001160 <exit@plt>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	f2 ff 25 5d 2e 00 00 	bnd jmp *0x2e5d(%rip)        # 3fc8 <exit@GLIBC_2.2.5>
    116b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001170 <fwrite@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 55 2e 00 00 	bnd jmp *0x2e55(%rip)        # 3fd0 <fwrite@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001180 <_start>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	31 ed                	xor    %ebp,%ebp
    1186:	49 89 d1             	mov    %rdx,%r9
    1189:	5e                   	pop    %rsi
    118a:	48 89 e2             	mov    %rsp,%rdx
    118d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1191:	50                   	push   %rax
    1192:	54                   	push   %rsp
    1193:	45 31 c0             	xor    %r8d,%r8d
    1196:	31 c9                	xor    %ecx,%ecx
    1198:	48 8d 3d 6d 05 00 00 	lea    0x56d(%rip),%rdi        # 170c <main>
    119f:	ff 15 33 2e 00 00    	call   *0x2e33(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    11a5:	f4                   	hlt    
    11a6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    11ad:	00 00 00 

00000000000011b0 <deregister_tm_clones>:
    11b0:	48 8d 3d 59 2e 00 00 	lea    0x2e59(%rip),%rdi        # 4010 <__TMC_END__>
    11b7:	48 8d 05 52 2e 00 00 	lea    0x2e52(%rip),%rax        # 4010 <__TMC_END__>
    11be:	48 39 f8             	cmp    %rdi,%rax
    11c1:	74 15                	je     11d8 <deregister_tm_clones+0x28>
    11c3:	48 8b 05 16 2e 00 00 	mov    0x2e16(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    11ca:	48 85 c0             	test   %rax,%rax
    11cd:	74 09                	je     11d8 <deregister_tm_clones+0x28>
    11cf:	ff e0                	jmp    *%rax
    11d1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    11d8:	c3                   	ret    
    11d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011e0 <register_tm_clones>:
    11e0:	48 8d 3d 29 2e 00 00 	lea    0x2e29(%rip),%rdi        # 4010 <__TMC_END__>
    11e7:	48 8d 35 22 2e 00 00 	lea    0x2e22(%rip),%rsi        # 4010 <__TMC_END__>
    11ee:	48 29 fe             	sub    %rdi,%rsi
    11f1:	48 89 f0             	mov    %rsi,%rax
    11f4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    11f8:	48 c1 f8 03          	sar    $0x3,%rax
    11fc:	48 01 c6             	add    %rax,%rsi
    11ff:	48 d1 fe             	sar    %rsi
    1202:	74 14                	je     1218 <register_tm_clones+0x38>
    1204:	48 8b 05 e5 2d 00 00 	mov    0x2de5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    120b:	48 85 c0             	test   %rax,%rax
    120e:	74 08                	je     1218 <register_tm_clones+0x38>
    1210:	ff e0                	jmp    *%rax
    1212:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1218:	c3                   	ret    
    1219:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001220 <__do_global_dtors_aux>:
    1220:	f3 0f 1e fa          	endbr64 
    1224:	80 3d 1d 2e 00 00 00 	cmpb   $0x0,0x2e1d(%rip)        # 4048 <completed.0>
    122b:	75 2b                	jne    1258 <__do_global_dtors_aux+0x38>
    122d:	55                   	push   %rbp
    122e:	48 83 3d c2 2d 00 00 	cmpq   $0x0,0x2dc2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1235:	00 
    1236:	48 89 e5             	mov    %rsp,%rbp
    1239:	74 0c                	je     1247 <__do_global_dtors_aux+0x27>
    123b:	48 8b 3d c6 2d 00 00 	mov    0x2dc6(%rip),%rdi        # 4008 <__dso_handle>
    1242:	e8 89 fe ff ff       	call   10d0 <__cxa_finalize@plt>
    1247:	e8 64 ff ff ff       	call   11b0 <deregister_tm_clones>
    124c:	c6 05 f5 2d 00 00 01 	movb   $0x1,0x2df5(%rip)        # 4048 <completed.0>
    1253:	5d                   	pop    %rbp
    1254:	c3                   	ret    
    1255:	0f 1f 00             	nopl   (%rax)
    1258:	c3                   	ret    
    1259:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001260 <frame_dummy>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	e9 77 ff ff ff       	jmp    11e0 <register_tm_clones>

0000000000001269 <print_path>:
    1269:	f3 0f 1e fa          	endbr64 
    126d:	55                   	push   %rbp
    126e:	48 89 e5             	mov    %rsp,%rbp
    1271:	48 83 ec 10          	sub    $0x10,%rsp
    1275:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1279:	89 75 f4             	mov    %esi,-0xc(%rbp)
    127c:	8b 45 f4             	mov    -0xc(%rbp),%eax
    127f:	48 98                	cltq   
    1281:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1288:	00 
    1289:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    128d:	48 01 d0             	add    %rdx,%rax
    1290:	8b 40 04             	mov    0x4(%rax),%eax
    1293:	3d 0f 27 00 00       	cmp    $0x270f,%eax
    1298:	74 25                	je     12bf <print_path+0x56>
    129a:	8b 45 f4             	mov    -0xc(%rbp),%eax
    129d:	48 98                	cltq   
    129f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    12a6:	00 
    12a7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    12ab:	48 01 d0             	add    %rdx,%rax
    12ae:	8b 50 04             	mov    0x4(%rax),%edx
    12b1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    12b5:	89 d6                	mov    %edx,%esi
    12b7:	48 89 c7             	mov    %rax,%rdi
    12ba:	e8 aa ff ff ff       	call   1269 <print_path>
    12bf:	8b 45 f4             	mov    -0xc(%rbp),%eax
    12c2:	89 c6                	mov    %eax,%esi
    12c4:	48 8d 05 3d 0d 00 00 	lea    0xd3d(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    12cb:	48 89 c7             	mov    %rax,%rdi
    12ce:	b8 00 00 00 00       	mov    $0x0,%eax
    12d3:	e8 48 fe ff ff       	call   1120 <printf@plt>
    12d8:	48 8b 05 41 2d 00 00 	mov    0x2d41(%rip),%rax        # 4020 <stdout@GLIBC_2.2.5>
    12df:	48 89 c7             	mov    %rax,%rdi
    12e2:	e8 59 fe ff ff       	call   1140 <fflush@plt>
    12e7:	90                   	nop
    12e8:	c9                   	leave  
    12e9:	c3                   	ret    

00000000000012ea <enqueue>:
    12ea:	f3 0f 1e fa          	endbr64 
    12ee:	55                   	push   %rbp
    12ef:	48 89 e5             	mov    %rsp,%rbp
    12f2:	48 83 ec 20          	sub    $0x20,%rsp
    12f6:	89 7d ec             	mov    %edi,-0x14(%rbp)
    12f9:	89 75 e8             	mov    %esi,-0x18(%rbp)
    12fc:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    12ff:	bf 18 00 00 00       	mov    $0x18,%edi
    1304:	e8 27 fe ff ff       	call   1130 <malloc@plt>
    1309:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    130d:	48 8b 05 4c 2d 00 00 	mov    0x2d4c(%rip),%rax        # 4060 <qHead>
    1314:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1318:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    131d:	75 2d                	jne    134c <enqueue+0x62>
    131f:	48 8b 05 1a 2d 00 00 	mov    0x2d1a(%rip),%rax        # 4040 <stderr@GLIBC_2.2.5>
    1326:	48 89 c1             	mov    %rax,%rcx
    1329:	ba 0f 00 00 00       	mov    $0xf,%edx
    132e:	be 01 00 00 00       	mov    $0x1,%esi
    1333:	48 8d 05 d2 0c 00 00 	lea    0xcd2(%rip),%rax        # 200c <_IO_stdin_used+0xc>
    133a:	48 89 c7             	mov    %rax,%rdi
    133d:	e8 2e fe ff ff       	call   1170 <fwrite@plt>
    1342:	bf 01 00 00 00       	mov    $0x1,%edi
    1347:	e8 14 fe ff ff       	call   1160 <exit@plt>
    134c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1350:	8b 55 ec             	mov    -0x14(%rbp),%edx
    1353:	89 10                	mov    %edx,(%rax)
    1355:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1359:	8b 55 e8             	mov    -0x18(%rbp),%edx
    135c:	89 50 04             	mov    %edx,0x4(%rax)
    135f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1363:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    1366:	89 50 08             	mov    %edx,0x8(%rax)
    1369:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    136d:	48 c7 40 10 00 00 00 	movq   $0x0,0x10(%rax)
    1374:	00 
    1375:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
    137a:	75 19                	jne    1395 <enqueue+0xab>
    137c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1380:	48 89 05 d9 2c 00 00 	mov    %rax,0x2cd9(%rip)        # 4060 <qHead>
    1387:	eb 25                	jmp    13ae <enqueue+0xc4>
    1389:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    138d:	48 8b 40 10          	mov    0x10(%rax),%rax
    1391:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    1395:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1399:	48 8b 40 10          	mov    0x10(%rax),%rax
    139d:	48 85 c0             	test   %rax,%rax
    13a0:	75 e7                	jne    1389 <enqueue+0x9f>
    13a2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    13a6:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    13aa:	48 89 50 10          	mov    %rdx,0x10(%rax)
    13ae:	8b 05 0c c9 00 00    	mov    0xc90c(%rip),%eax        # dcc0 <g_qCount>
    13b4:	83 c0 01             	add    $0x1,%eax
    13b7:	89 05 03 c9 00 00    	mov    %eax,0xc903(%rip)        # dcc0 <g_qCount>
    13bd:	90                   	nop
    13be:	c9                   	leave  
    13bf:	c3                   	ret    

00000000000013c0 <dequeue>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	55                   	push   %rbp
    13c5:	48 89 e5             	mov    %rsp,%rbp
    13c8:	48 83 ec 30          	sub    $0x30,%rsp
    13cc:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    13d0:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    13d4:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
    13d8:	48 8b 05 81 2c 00 00 	mov    0x2c81(%rip),%rax        # 4060 <qHead>
    13df:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    13e3:	48 8b 05 76 2c 00 00 	mov    0x2c76(%rip),%rax        # 4060 <qHead>
    13ea:	48 85 c0             	test   %rax,%rax
    13ed:	74 5c                	je     144b <dequeue+0x8b>
    13ef:	48 8b 05 6a 2c 00 00 	mov    0x2c6a(%rip),%rax        # 4060 <qHead>
    13f6:	8b 10                	mov    (%rax),%edx
    13f8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    13fc:	89 10                	mov    %edx,(%rax)
    13fe:	48 8b 05 5b 2c 00 00 	mov    0x2c5b(%rip),%rax        # 4060 <qHead>
    1405:	8b 50 04             	mov    0x4(%rax),%edx
    1408:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    140c:	89 10                	mov    %edx,(%rax)
    140e:	48 8b 05 4b 2c 00 00 	mov    0x2c4b(%rip),%rax        # 4060 <qHead>
    1415:	8b 50 08             	mov    0x8(%rax),%edx
    1418:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    141c:	89 10                	mov    %edx,(%rax)
    141e:	48 8b 05 3b 2c 00 00 	mov    0x2c3b(%rip),%rax        # 4060 <qHead>
    1425:	48 8b 40 10          	mov    0x10(%rax),%rax
    1429:	48 89 05 30 2c 00 00 	mov    %rax,0x2c30(%rip)        # 4060 <qHead>
    1430:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1434:	48 89 c7             	mov    %rax,%rdi
    1437:	e8 a4 fc ff ff       	call   10e0 <free@plt>
    143c:	8b 05 7e c8 00 00    	mov    0xc87e(%rip),%eax        # dcc0 <g_qCount>
    1442:	83 e8 01             	sub    $0x1,%eax
    1445:	89 05 75 c8 00 00    	mov    %eax,0xc875(%rip)        # dcc0 <g_qCount>
    144b:	90                   	nop
    144c:	c9                   	leave  
    144d:	c3                   	ret    

000000000000144e <qcount>:
    144e:	f3 0f 1e fa          	endbr64 
    1452:	55                   	push   %rbp
    1453:	48 89 e5             	mov    %rsp,%rbp
    1456:	8b 05 64 c8 00 00    	mov    0xc864(%rip),%eax        # dcc0 <g_qCount>
    145c:	5d                   	pop    %rbp
    145d:	c3                   	ret    

000000000000145e <dijkstra>:
    145e:	f3 0f 1e fa          	endbr64 
    1462:	55                   	push   %rbp
    1463:	48 89 e5             	mov    %rsp,%rbp
    1466:	48 83 ec 10          	sub    $0x10,%rsp
    146a:	89 7d fc             	mov    %edi,-0x4(%rbp)
    146d:	89 75 f8             	mov    %esi,-0x8(%rbp)
    1470:	c7 05 86 cb 00 00 00 	movl   $0x0,0xcb86(%rip)        # e000 <ch>
    1477:	00 00 00 
    147a:	eb 4b                	jmp    14c7 <dijkstra+0x69>
    147c:	8b 05 7e cb 00 00    	mov    0xcb7e(%rip),%eax        # e000 <ch>
    1482:	48 98                	cltq   
    1484:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    148b:	00 
    148c:	48 8d 05 4d c8 00 00 	lea    0xc84d(%rip),%rax        # dce0 <rgnNodes>
    1493:	c7 04 02 0f 27 00 00 	movl   $0x270f,(%rdx,%rax,1)
    149a:	8b 05 60 cb 00 00    	mov    0xcb60(%rip),%eax        # e000 <ch>
    14a0:	48 98                	cltq   
    14a2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    14a9:	00 
    14aa:	48 8d 05 33 c8 00 00 	lea    0xc833(%rip),%rax        # dce4 <rgnNodes+0x4>
    14b1:	c7 04 02 0f 27 00 00 	movl   $0x270f,(%rdx,%rax,1)
    14b8:	8b 05 42 cb 00 00    	mov    0xcb42(%rip),%eax        # e000 <ch>
    14be:	83 c0 01             	add    $0x1,%eax
    14c1:	89 05 39 cb 00 00    	mov    %eax,0xcb39(%rip)        # e000 <ch>
    14c7:	8b 05 33 cb 00 00    	mov    0xcb33(%rip),%eax        # e000 <ch>
    14cd:	83 f8 63             	cmp    $0x63,%eax
    14d0:	7e aa                	jle    147c <dijkstra+0x1e>
    14d2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    14d5:	3b 45 f8             	cmp    -0x8(%rbp),%eax
    14d8:	75 14                	jne    14ee <dijkstra+0x90>
    14da:	48 8d 05 3f 0b 00 00 	lea    0xb3f(%rip),%rax        # 2020 <_IO_stdin_used+0x20>
    14e1:	48 89 c7             	mov    %rax,%rdi
    14e4:	e8 27 fc ff ff       	call   1110 <puts@plt>
    14e9:	e9 1b 02 00 00       	jmp    1709 <dijkstra+0x2ab>
    14ee:	8b 45 fc             	mov    -0x4(%rbp),%eax
    14f1:	48 98                	cltq   
    14f3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    14fa:	00 
    14fb:	48 8d 05 de c7 00 00 	lea    0xc7de(%rip),%rax        # dce0 <rgnNodes>
    1502:	c7 04 02 00 00 00 00 	movl   $0x0,(%rdx,%rax,1)
    1509:	8b 45 fc             	mov    -0x4(%rbp),%eax
    150c:	48 98                	cltq   
    150e:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1515:	00 
    1516:	48 8d 05 c7 c7 00 00 	lea    0xc7c7(%rip),%rax        # dce4 <rgnNodes+0x4>
    151d:	c7 04 02 0f 27 00 00 	movl   $0x270f,(%rdx,%rax,1)
    1524:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1527:	ba 0f 27 00 00       	mov    $0x270f,%edx
    152c:	be 00 00 00 00       	mov    $0x0,%esi
    1531:	89 c7                	mov    %eax,%edi
    1533:	e8 b2 fd ff ff       	call   12ea <enqueue>
    1538:	e9 60 01 00 00       	jmp    169d <dijkstra+0x23f>
    153d:	48 8d 05 c0 ca 00 00 	lea    0xcac0(%rip),%rax        # e004 <iPrev>
    1544:	48 89 c2             	mov    %rax,%rdx
    1547:	48 8d 05 c6 ca 00 00 	lea    0xcac6(%rip),%rax        # e014 <iDist>
    154e:	48 89 c6             	mov    %rax,%rsi
    1551:	48 8d 05 b0 ca 00 00 	lea    0xcab0(%rip),%rax        # e008 <iNode>
    1558:	48 89 c7             	mov    %rax,%rdi
    155b:	e8 60 fe ff ff       	call   13c0 <dequeue>
    1560:	c7 05 a2 ca 00 00 00 	movl   $0x0,0xcaa2(%rip)        # e00c <i>
    1567:	00 00 00 
    156a:	e9 1f 01 00 00       	jmp    168e <dijkstra+0x230>
    156f:	8b 05 93 ca 00 00    	mov    0xca93(%rip),%eax        # e008 <iNode>
    1575:	8b 15 91 ca 00 00    	mov    0xca91(%rip),%edx        # e00c <i>
    157b:	48 63 ca             	movslq %edx,%rcx
    157e:	48 63 d0             	movslq %eax,%rdx
    1581:	48 89 d0             	mov    %rdx,%rax
    1584:	48 c1 e0 02          	shl    $0x2,%rax
    1588:	48 01 d0             	add    %rdx,%rax
    158b:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    1592:	00 
    1593:	48 01 d0             	add    %rdx,%rax
    1596:	48 c1 e0 02          	shl    $0x2,%rax
    159a:	48 01 c8             	add    %rcx,%rax
    159d:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    15a4:	00 
    15a5:	48 8d 05 d4 2a 00 00 	lea    0x2ad4(%rip),%rax        # 4080 <AdjMatrix>
    15ac:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    15af:	89 05 5b ca 00 00    	mov    %eax,0xca5b(%rip)        # e010 <iCost>
    15b5:	8b 05 55 ca 00 00    	mov    0xca55(%rip),%eax        # e010 <iCost>
    15bb:	3d 0f 27 00 00       	cmp    $0x270f,%eax
    15c0:	0f 84 b9 00 00 00    	je     167f <dijkstra+0x221>
    15c6:	8b 05 40 ca 00 00    	mov    0xca40(%rip),%eax        # e00c <i>
    15cc:	48 98                	cltq   
    15ce:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    15d5:	00 
    15d6:	48 8d 05 03 c7 00 00 	lea    0xc703(%rip),%rax        # dce0 <rgnNodes>
    15dd:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    15e0:	3d 0f 27 00 00       	cmp    $0x270f,%eax
    15e5:	74 2c                	je     1613 <dijkstra+0x1b5>
    15e7:	8b 05 1f ca 00 00    	mov    0xca1f(%rip),%eax        # e00c <i>
    15ed:	48 98                	cltq   
    15ef:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    15f6:	00 
    15f7:	48 8d 05 e2 c6 00 00 	lea    0xc6e2(%rip),%rax        # dce0 <rgnNodes>
    15fe:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    1601:	8b 0d 09 ca 00 00    	mov    0xca09(%rip),%ecx        # e010 <iCost>
    1607:	8b 15 07 ca 00 00    	mov    0xca07(%rip),%edx        # e014 <iDist>
    160d:	01 ca                	add    %ecx,%edx
    160f:	39 d0                	cmp    %edx,%eax
    1611:	7e 6c                	jle    167f <dijkstra+0x221>
    1613:	8b 0d fb c9 00 00    	mov    0xc9fb(%rip),%ecx        # e014 <iDist>
    1619:	8b 15 f1 c9 00 00    	mov    0xc9f1(%rip),%edx        # e010 <iCost>
    161f:	8b 05 e7 c9 00 00    	mov    0xc9e7(%rip),%eax        # e00c <i>
    1625:	01 d1                	add    %edx,%ecx
    1627:	48 98                	cltq   
    1629:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    1630:	00 
    1631:	48 8d 05 a8 c6 00 00 	lea    0xc6a8(%rip),%rax        # dce0 <rgnNodes>
    1638:	89 0c 02             	mov    %ecx,(%rdx,%rax,1)
    163b:	8b 15 cb c9 00 00    	mov    0xc9cb(%rip),%edx        # e00c <i>
    1641:	8b 05 c1 c9 00 00    	mov    0xc9c1(%rip),%eax        # e008 <iNode>
    1647:	48 63 d2             	movslq %edx,%rdx
    164a:	48 8d 0c d5 00 00 00 	lea    0x0(,%rdx,8),%rcx
    1651:	00 
    1652:	48 8d 15 8b c6 00 00 	lea    0xc68b(%rip),%rdx        # dce4 <rgnNodes+0x4>
    1659:	89 04 11             	mov    %eax,(%rcx,%rdx,1)
    165c:	8b 15 a6 c9 00 00    	mov    0xc9a6(%rip),%edx        # e008 <iNode>
    1662:	8b 0d ac c9 00 00    	mov    0xc9ac(%rip),%ecx        # e014 <iDist>
    1668:	8b 05 a2 c9 00 00    	mov    0xc9a2(%rip),%eax        # e010 <iCost>
    166e:	01 c1                	add    %eax,%ecx
    1670:	8b 05 96 c9 00 00    	mov    0xc996(%rip),%eax        # e00c <i>
    1676:	89 ce                	mov    %ecx,%esi
    1678:	89 c7                	mov    %eax,%edi
    167a:	e8 6b fc ff ff       	call   12ea <enqueue>
    167f:	8b 05 87 c9 00 00    	mov    0xc987(%rip),%eax        # e00c <i>
    1685:	83 c0 01             	add    $0x1,%eax
    1688:	89 05 7e c9 00 00    	mov    %eax,0xc97e(%rip)        # e00c <i>
    168e:	8b 05 78 c9 00 00    	mov    0xc978(%rip),%eax        # e00c <i>
    1694:	83 f8 63             	cmp    $0x63,%eax
    1697:	0f 8e d2 fe ff ff    	jle    156f <dijkstra+0x111>
    169d:	e8 ac fd ff ff       	call   144e <qcount>
    16a2:	85 c0                	test   %eax,%eax
    16a4:	0f 8f 93 fe ff ff    	jg     153d <dijkstra+0xdf>
    16aa:	8b 45 f8             	mov    -0x8(%rbp),%eax
    16ad:	48 98                	cltq   
    16af:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
    16b6:	00 
    16b7:	48 8d 05 22 c6 00 00 	lea    0xc622(%rip),%rax        # dce0 <rgnNodes>
    16be:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    16c1:	89 c6                	mov    %eax,%esi
    16c3:	48 8d 05 8b 09 00 00 	lea    0x98b(%rip),%rax        # 2055 <_IO_stdin_used+0x55>
    16ca:	48 89 c7             	mov    %rax,%rdi
    16cd:	b8 00 00 00 00       	mov    $0x0,%eax
    16d2:	e8 49 fa ff ff       	call   1120 <printf@plt>
    16d7:	48 8d 05 95 09 00 00 	lea    0x995(%rip),%rax        # 2073 <_IO_stdin_used+0x73>
    16de:	48 89 c7             	mov    %rax,%rdi
    16e1:	b8 00 00 00 00       	mov    $0x0,%eax
    16e6:	e8 35 fa ff ff       	call   1120 <printf@plt>
    16eb:	8b 45 f8             	mov    -0x8(%rbp),%eax
    16ee:	89 c6                	mov    %eax,%esi
    16f0:	48 8d 05 e9 c5 00 00 	lea    0xc5e9(%rip),%rax        # dce0 <rgnNodes>
    16f7:	48 89 c7             	mov    %rax,%rdi
    16fa:	e8 6a fb ff ff       	call   1269 <print_path>
    16ff:	bf 0a 00 00 00       	mov    $0xa,%edi
    1704:	e8 e7 f9 ff ff       	call   10f0 <putchar@plt>
    1709:	90                   	nop
    170a:	c9                   	leave  
    170b:	c3                   	ret    

000000000000170c <main>:
    170c:	f3 0f 1e fa          	endbr64 
    1710:	55                   	push   %rbp
    1711:	48 89 e5             	mov    %rsp,%rbp
    1714:	48 83 ec 30          	sub    $0x30,%rsp
    1718:	89 7d dc             	mov    %edi,-0x24(%rbp)
    171b:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
    171f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1726:	00 00 
    1728:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    172c:	31 c0                	xor    %eax,%eax
    172e:	83 7d dc 01          	cmpl   $0x1,-0x24(%rbp)
    1732:	7f 46                	jg     177a <main+0x6e>
    1734:	48 8b 05 05 29 00 00 	mov    0x2905(%rip),%rax        # 4040 <stderr@GLIBC_2.2.5>
    173b:	48 89 c1             	mov    %rax,%rcx
    173e:	ba 1b 00 00 00       	mov    $0x1b,%edx
    1743:	be 01 00 00 00       	mov    $0x1,%esi
    1748:	48 8d 05 2e 09 00 00 	lea    0x92e(%rip),%rax        # 207d <_IO_stdin_used+0x7d>
    174f:	48 89 c7             	mov    %rax,%rdi
    1752:	e8 19 fa ff ff       	call   1170 <fwrite@plt>
    1757:	48 8b 05 e2 28 00 00 	mov    0x28e2(%rip),%rax        # 4040 <stderr@GLIBC_2.2.5>
    175e:	48 89 c1             	mov    %rax,%rcx
    1761:	ba 28 00 00 00       	mov    $0x28,%edx
    1766:	be 01 00 00 00       	mov    $0x1,%esi
    176b:	48 8d 05 2e 09 00 00 	lea    0x92e(%rip),%rax        # 20a0 <_IO_stdin_used+0xa0>
    1772:	48 89 c7             	mov    %rax,%rdi
    1775:	e8 f6 f9 ff ff       	call   1170 <fwrite@plt>
    177a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
    177e:	48 83 c0 08          	add    $0x8,%rax
    1782:	48 8b 00             	mov    (%rax),%rax
    1785:	48 8d 15 3d 09 00 00 	lea    0x93d(%rip),%rdx        # 20c9 <_IO_stdin_used+0xc9>
    178c:	48 89 d6             	mov    %rdx,%rsi
    178f:	48 89 c7             	mov    %rax,%rdi
    1792:	e8 b9 f9 ff ff       	call   1150 <fopen@plt>
    1797:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    179b:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    17a2:	eb 73                	jmp    1817 <main+0x10b>
    17a4:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    17ab:	eb 60                	jmp    180d <main+0x101>
    17ad:	48 8d 55 e4          	lea    -0x1c(%rbp),%rdx
    17b1:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    17b5:	48 8d 0d 0f 09 00 00 	lea    0x90f(%rip),%rcx        # 20cb <_IO_stdin_used+0xcb>
    17bc:	48 89 ce             	mov    %rcx,%rsi
    17bf:	48 89 c7             	mov    %rax,%rdi
    17c2:	b8 00 00 00 00       	mov    $0x0,%eax
    17c7:	e8 34 f9 ff ff       	call   1100 <__isoc99_fscanf@plt>
    17cc:	8b 55 e4             	mov    -0x1c(%rbp),%edx
    17cf:	8b 45 ec             	mov    -0x14(%rbp),%eax
    17d2:	48 63 f0             	movslq %eax,%rsi
    17d5:	8b 45 e8             	mov    -0x18(%rbp),%eax
    17d8:	48 63 c8             	movslq %eax,%rcx
    17db:	48 89 c8             	mov    %rcx,%rax
    17de:	48 c1 e0 02          	shl    $0x2,%rax
    17e2:	48 01 c8             	add    %rcx,%rax
    17e5:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    17ec:	00 
    17ed:	48 01 c8             	add    %rcx,%rax
    17f0:	48 c1 e0 02          	shl    $0x2,%rax
    17f4:	48 01 f0             	add    %rsi,%rax
    17f7:	48 8d 0c 85 00 00 00 	lea    0x0(,%rax,4),%rcx
    17fe:	00 
    17ff:	48 8d 05 7a 28 00 00 	lea    0x287a(%rip),%rax        # 4080 <AdjMatrix>
    1806:	89 14 01             	mov    %edx,(%rcx,%rax,1)
    1809:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    180d:	83 7d ec 63          	cmpl   $0x63,-0x14(%rbp)
    1811:	7e 9a                	jle    17ad <main+0xa1>
    1813:	83 45 e8 01          	addl   $0x1,-0x18(%rbp)
    1817:	83 7d e8 63          	cmpl   $0x63,-0x18(%rbp)
    181b:	7e 87                	jle    17a4 <main+0x98>
    181d:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
    1824:	c7 45 ec 32 00 00 00 	movl   $0x32,-0x14(%rbp)
    182b:	eb 3a                	jmp    1867 <main+0x15b>
    182d:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1830:	48 63 d0             	movslq %eax,%rdx
    1833:	48 69 d2 1f 85 eb 51 	imul   $0x51eb851f,%rdx,%rdx
    183a:	48 c1 ea 20          	shr    $0x20,%rdx
    183e:	c1 fa 05             	sar    $0x5,%edx
    1841:	89 c1                	mov    %eax,%ecx
    1843:	c1 f9 1f             	sar    $0x1f,%ecx
    1846:	29 ca                	sub    %ecx,%edx
    1848:	6b d2 64             	imul   $0x64,%edx,%edx
    184b:	29 d0                	sub    %edx,%eax
    184d:	89 45 ec             	mov    %eax,-0x14(%rbp)
    1850:	8b 55 ec             	mov    -0x14(%rbp),%edx
    1853:	8b 45 e8             	mov    -0x18(%rbp),%eax
    1856:	89 d6                	mov    %edx,%esi
    1858:	89 c7                	mov    %eax,%edi
    185a:	e8 ff fb ff ff       	call   145e <dijkstra>
    185f:	83 45 e8 01          	addl   $0x1,-0x18(%rbp)
    1863:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    1867:	83 7d e8 63          	cmpl   $0x63,-0x18(%rbp)
    186b:	7e c0                	jle    182d <main+0x121>
    186d:	bf 00 00 00 00       	mov    $0x0,%edi
    1872:	e8 e9 f8 ff ff       	call   1160 <exit@plt>

Disassembly of section .fini:

0000000000001878 <_fini>:
    1878:	f3 0f 1e fa          	endbr64 
    187c:	48 83 ec 08          	sub    $0x8,%rsp
    1880:	48 83 c4 08          	add    $0x8,%rsp
    1884:	c3                   	ret    
