
/usr/local/software/mibench/automotive/qsort/qsort_large:     file format elf64-x86-64


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
    1020:	ff 35 5a 2f 00 00    	push   0x2f5a(%rip)        # 3f80 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 5b 2f 00 00 	bnd jmp *0x2f5b(%rip)        # 3f88 <_GLOBAL_OFFSET_TABLE_+0x10>
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

Disassembly of section .plt.got:

00000000000010c0 <__cxa_finalize@plt>:
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	f2 ff 25 2d 2f 00 00 	bnd jmp *0x2f2d(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

00000000000010d0 <__isoc99_fscanf@plt>:
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	f2 ff 25 b5 2e 00 00 	bnd jmp *0x2eb5(%rip)        # 3f90 <__isoc99_fscanf@GLIBC_2.7>
    10db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010e0 <qsort@plt>:
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	f2 ff 25 ad 2e 00 00 	bnd jmp *0x2ead(%rip)        # 3f98 <qsort@GLIBC_2.2.5>
    10eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000010f0 <pow@plt>:
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	f2 ff 25 a5 2e 00 00 	bnd jmp *0x2ea5(%rip)        # 3fa0 <pow@GLIBC_2.29>
    10fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001100 <__stack_chk_fail@plt>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	f2 ff 25 9d 2e 00 00 	bnd jmp *0x2e9d(%rip)        # 3fa8 <__stack_chk_fail@GLIBC_2.4>
    110b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001110 <printf@plt>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	f2 ff 25 95 2e 00 00 	bnd jmp *0x2e95(%rip)        # 3fb0 <printf@GLIBC_2.2.5>
    111b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001120 <fopen@plt>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	f2 ff 25 8d 2e 00 00 	bnd jmp *0x2e8d(%rip)        # 3fb8 <fopen@GLIBC_2.2.5>
    112b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001130 <exit@plt>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	f2 ff 25 85 2e 00 00 	bnd jmp *0x2e85(%rip)        # 3fc0 <exit@GLIBC_2.2.5>
    113b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001140 <fwrite@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 7d 2e 00 00 	bnd jmp *0x2e7d(%rip)        # 3fc8 <fwrite@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001150 <sqrt@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 75 2e 00 00 	bnd jmp *0x2e75(%rip)        # 3fd0 <sqrt@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001160 <_start>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	31 ed                	xor    %ebp,%ebp
    1166:	49 89 d1             	mov    %rdx,%r9
    1169:	5e                   	pop    %rsi
    116a:	48 89 e2             	mov    %rsp,%rdx
    116d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1171:	50                   	push   %rax
    1172:	54                   	push   %rsp
    1173:	45 31 c0             	xor    %r8d,%r8d
    1176:	31 c9                	xor    %ecx,%ecx
    1178:	48 8d 3d 2f 01 00 00 	lea    0x12f(%rip),%rdi        # 12ae <main>
    117f:	ff 15 53 2e 00 00    	call   *0x2e53(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1185:	f4                   	hlt    
    1186:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    118d:	00 00 00 

0000000000001190 <deregister_tm_clones>:
    1190:	48 8d 3d 79 2e 00 00 	lea    0x2e79(%rip),%rdi        # 4010 <__TMC_END__>
    1197:	48 8d 05 72 2e 00 00 	lea    0x2e72(%rip),%rax        # 4010 <__TMC_END__>
    119e:	48 39 f8             	cmp    %rdi,%rax
    11a1:	74 15                	je     11b8 <deregister_tm_clones+0x28>
    11a3:	48 8b 05 36 2e 00 00 	mov    0x2e36(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    11aa:	48 85 c0             	test   %rax,%rax
    11ad:	74 09                	je     11b8 <deregister_tm_clones+0x28>
    11af:	ff e0                	jmp    *%rax
    11b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    11b8:	c3                   	ret    
    11b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000011c0 <register_tm_clones>:
    11c0:	48 8d 3d 49 2e 00 00 	lea    0x2e49(%rip),%rdi        # 4010 <__TMC_END__>
    11c7:	48 8d 35 42 2e 00 00 	lea    0x2e42(%rip),%rsi        # 4010 <__TMC_END__>
    11ce:	48 29 fe             	sub    %rdi,%rsi
    11d1:	48 89 f0             	mov    %rsi,%rax
    11d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    11d8:	48 c1 f8 03          	sar    $0x3,%rax
    11dc:	48 01 c6             	add    %rax,%rsi
    11df:	48 d1 fe             	sar    %rsi
    11e2:	74 14                	je     11f8 <register_tm_clones+0x38>
    11e4:	48 8b 05 05 2e 00 00 	mov    0x2e05(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    11eb:	48 85 c0             	test   %rax,%rax
    11ee:	74 08                	je     11f8 <register_tm_clones+0x38>
    11f0:	ff e0                	jmp    *%rax
    11f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    11f8:	c3                   	ret    
    11f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001200 <__do_global_dtors_aux>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	80 3d 1d 2e 00 00 00 	cmpb   $0x0,0x2e1d(%rip)        # 4028 <completed.0>
    120b:	75 2b                	jne    1238 <__do_global_dtors_aux+0x38>
    120d:	55                   	push   %rbp
    120e:	48 83 3d e2 2d 00 00 	cmpq   $0x0,0x2de2(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1215:	00 
    1216:	48 89 e5             	mov    %rsp,%rbp
    1219:	74 0c                	je     1227 <__do_global_dtors_aux+0x27>
    121b:	48 8b 3d e6 2d 00 00 	mov    0x2de6(%rip),%rdi        # 4008 <__dso_handle>
    1222:	e8 99 fe ff ff       	call   10c0 <__cxa_finalize@plt>
    1227:	e8 64 ff ff ff       	call   1190 <deregister_tm_clones>
    122c:	c6 05 f5 2d 00 00 01 	movb   $0x1,0x2df5(%rip)        # 4028 <completed.0>
    1233:	5d                   	pop    %rbp
    1234:	c3                   	ret    
    1235:	0f 1f 00             	nopl   (%rax)
    1238:	c3                   	ret    
    1239:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001240 <frame_dummy>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	e9 77 ff ff ff       	jmp    11c0 <register_tm_clones>

0000000000001249 <compare>:
    1249:	f3 0f 1e fa          	endbr64 
    124d:	55                   	push   %rbp
    124e:	48 89 e5             	mov    %rsp,%rbp
    1251:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1255:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    1259:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    125d:	f2 0f 10 40 10       	movsd  0x10(%rax),%xmm0
    1262:	f2 0f 11 45 f0       	movsd  %xmm0,-0x10(%rbp)
    1267:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    126b:	f2 0f 10 40 10       	movsd  0x10(%rax),%xmm0
    1270:	f2 0f 11 45 f8       	movsd  %xmm0,-0x8(%rbp)
    1275:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    127a:	66 0f 2f 45 f8       	comisd -0x8(%rbp),%xmm0
    127f:	76 07                	jbe    1288 <compare+0x3f>
    1281:	b8 01 00 00 00       	mov    $0x1,%eax
    1286:	eb 24                	jmp    12ac <compare+0x63>
    1288:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    128d:	66 0f 2e 45 f8       	ucomisd -0x8(%rbp),%xmm0
    1292:	7a 13                	jp     12a7 <compare+0x5e>
    1294:	f2 0f 10 45 f0       	movsd  -0x10(%rbp),%xmm0
    1299:	66 0f 2e 45 f8       	ucomisd -0x8(%rbp),%xmm0
    129e:	75 07                	jne    12a7 <compare+0x5e>
    12a0:	b8 00 00 00 00       	mov    $0x0,%eax
    12a5:	eb 05                	jmp    12ac <compare+0x63>
    12a7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    12ac:	5d                   	pop    %rbp
    12ad:	c3                   	ret    

00000000000012ae <main>:
    12ae:	f3 0f 1e fa          	endbr64 
    12b2:	55                   	push   %rbp
    12b3:	48 89 e5             	mov    %rsp,%rbp
    12b6:	4c 8d 9c 24 00 10 ea 	lea    -0x15f000(%rsp),%r11
    12bd:	ff 
    12be:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    12c5:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    12ca:	4c 39 dc             	cmp    %r11,%rsp
    12cd:	75 ef                	jne    12be <main+0x10>
    12cf:	48 81 ec 50 09 00 00 	sub    $0x950,%rsp
    12d6:	89 bd cc 06 ea ff    	mov    %edi,-0x15f934(%rbp)
    12dc:	48 89 b5 c0 06 ea ff 	mov    %rsi,-0x15f940(%rbp)
    12e3:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    12ea:	00 00 
    12ec:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    12f0:	31 c0                	xor    %eax,%eax
    12f2:	c7 85 e4 06 ea ff 00 	movl   $0x0,-0x15f91c(%rbp)
    12f9:	00 00 00 
    12fc:	83 bd cc 06 ea ff 01 	cmpl   $0x1,-0x15f934(%rbp)
    1303:	7f 2d                	jg     1332 <main+0x84>
    1305:	48 8b 05 14 2d 00 00 	mov    0x2d14(%rip),%rax        # 4020 <stderr@GLIBC_2.2.5>
    130c:	48 89 c1             	mov    %rax,%rcx
    130f:	ba 1a 00 00 00       	mov    $0x1a,%edx
    1314:	be 01 00 00 00       	mov    $0x1,%esi
    1319:	48 8d 05 e8 0c 00 00 	lea    0xce8(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    1320:	48 89 c7             	mov    %rax,%rdi
    1323:	e8 18 fe ff ff       	call   1140 <fwrite@plt>
    1328:	bf ff ff ff ff       	mov    $0xffffffff,%edi
    132d:	e8 fe fd ff ff       	call   1130 <exit@plt>
    1332:	48 8b 85 c0 06 ea ff 	mov    -0x15f940(%rbp),%rax
    1339:	48 83 c0 08          	add    $0x8,%rax
    133d:	48 8b 00             	mov    (%rax),%rax
    1340:	48 8d 15 dc 0c 00 00 	lea    0xcdc(%rip),%rdx        # 2023 <_IO_stdin_used+0x23>
    1347:	48 89 d6             	mov    %rdx,%rsi
    134a:	48 89 c7             	mov    %rax,%rdi
    134d:	e8 ce fd ff ff       	call   1120 <fopen@plt>
    1352:	48 89 85 e8 06 ea ff 	mov    %rax,-0x15f918(%rbp)
    1359:	e9 51 01 00 00       	jmp    14af <main+0x201>
    135e:	8b 95 d4 06 ea ff    	mov    -0x15f92c(%rbp),%edx
    1364:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    136a:	48 63 c8             	movslq %eax,%rcx
    136d:	48 89 c8             	mov    %rcx,%rax
    1370:	48 01 c0             	add    %rax,%rax
    1373:	48 01 c8             	add    %rcx,%rax
    1376:	48 c1 e0 03          	shl    $0x3,%rax
    137a:	48 01 e8             	add    %rbp,%rax
    137d:	48 2d 10 f9 15 00    	sub    $0x15f910,%rax
    1383:	89 10                	mov    %edx,(%rax)
    1385:	8b 95 d8 06 ea ff    	mov    -0x15f928(%rbp),%edx
    138b:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    1391:	48 63 c8             	movslq %eax,%rcx
    1394:	48 89 c8             	mov    %rcx,%rax
    1397:	48 01 c0             	add    %rax,%rax
    139a:	48 01 c8             	add    %rcx,%rax
    139d:	48 c1 e0 03          	shl    $0x3,%rax
    13a1:	48 01 e8             	add    %rbp,%rax
    13a4:	48 2d 0c f9 15 00    	sub    $0x15f90c,%rax
    13aa:	89 10                	mov    %edx,(%rax)
    13ac:	8b 95 dc 06 ea ff    	mov    -0x15f924(%rbp),%edx
    13b2:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    13b8:	48 63 c8             	movslq %eax,%rcx
    13bb:	48 89 c8             	mov    %rcx,%rax
    13be:	48 01 c0             	add    %rax,%rax
    13c1:	48 01 c8             	add    %rcx,%rax
    13c4:	48 c1 e0 03          	shl    $0x3,%rax
    13c8:	48 01 e8             	add    %rbp,%rax
    13cb:	48 2d 08 f9 15 00    	sub    $0x15f908,%rax
    13d1:	89 10                	mov    %edx,(%rax)
    13d3:	8b 85 d4 06 ea ff    	mov    -0x15f92c(%rbp),%eax
    13d9:	66 0f ef db          	pxor   %xmm3,%xmm3
    13dd:	f2 0f 2a d8          	cvtsi2sd %eax,%xmm3
    13e1:	66 48 0f 7e d8       	movq   %xmm3,%rax
    13e6:	f2 0f 10 05 82 0c 00 	movsd  0xc82(%rip),%xmm0        # 2070 <_IO_stdin_used+0x70>
    13ed:	00 
    13ee:	66 0f 28 c8          	movapd %xmm0,%xmm1
    13f2:	66 48 0f 6e c0       	movq   %rax,%xmm0
    13f7:	e8 f4 fc ff ff       	call   10f0 <pow@plt>
    13fc:	f2 0f 11 85 b8 06 ea 	movsd  %xmm0,-0x15f948(%rbp)
    1403:	ff 
    1404:	8b 85 d8 06 ea ff    	mov    -0x15f928(%rbp),%eax
    140a:	66 0f ef e4          	pxor   %xmm4,%xmm4
    140e:	f2 0f 2a e0          	cvtsi2sd %eax,%xmm4
    1412:	66 48 0f 7e e0       	movq   %xmm4,%rax
    1417:	f2 0f 10 05 51 0c 00 	movsd  0xc51(%rip),%xmm0        # 2070 <_IO_stdin_used+0x70>
    141e:	00 
    141f:	66 0f 28 c8          	movapd %xmm0,%xmm1
    1423:	66 48 0f 6e c0       	movq   %rax,%xmm0
    1428:	e8 c3 fc ff ff       	call   10f0 <pow@plt>
    142d:	66 0f 28 d0          	movapd %xmm0,%xmm2
    1431:	f2 0f 58 95 b8 06 ea 	addsd  -0x15f948(%rbp),%xmm2
    1438:	ff 
    1439:	f2 0f 11 95 b8 06 ea 	movsd  %xmm2,-0x15f948(%rbp)
    1440:	ff 
    1441:	8b 85 dc 06 ea ff    	mov    -0x15f924(%rbp),%eax
    1447:	66 0f ef f6          	pxor   %xmm6,%xmm6
    144b:	f2 0f 2a f0          	cvtsi2sd %eax,%xmm6
    144f:	66 48 0f 7e f0       	movq   %xmm6,%rax
    1454:	f2 0f 10 05 14 0c 00 	movsd  0xc14(%rip),%xmm0        # 2070 <_IO_stdin_used+0x70>
    145b:	00 
    145c:	66 0f 28 c8          	movapd %xmm0,%xmm1
    1460:	66 48 0f 6e c0       	movq   %rax,%xmm0
    1465:	e8 86 fc ff ff       	call   10f0 <pow@plt>
    146a:	f2 0f 58 85 b8 06 ea 	addsd  -0x15f948(%rbp),%xmm0
    1471:	ff 
    1472:	66 48 0f 7e c0       	movq   %xmm0,%rax
    1477:	66 48 0f 6e c0       	movq   %rax,%xmm0
    147c:	e8 cf fc ff ff       	call   1150 <sqrt@plt>
    1481:	66 48 0f 7e c2       	movq   %xmm0,%rdx
    1486:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    148c:	48 63 c8             	movslq %eax,%rcx
    148f:	48 89 c8             	mov    %rcx,%rax
    1492:	48 01 c0             	add    %rax,%rax
    1495:	48 01 c8             	add    %rcx,%rax
    1498:	48 c1 e0 03          	shl    $0x3,%rax
    149c:	48 01 e8             	add    %rbp,%rax
    149f:	48 2d 00 f9 15 00    	sub    $0x15f900,%rax
    14a5:	48 89 10             	mov    %rdx,(%rax)
    14a8:	83 85 e4 06 ea ff 01 	addl   $0x1,-0x15f91c(%rbp)
    14af:	48 8d 95 d4 06 ea ff 	lea    -0x15f92c(%rbp),%rdx
    14b6:	48 8b 85 e8 06 ea ff 	mov    -0x15f918(%rbp),%rax
    14bd:	48 8d 0d 61 0b 00 00 	lea    0xb61(%rip),%rcx        # 2025 <_IO_stdin_used+0x25>
    14c4:	48 89 ce             	mov    %rcx,%rsi
    14c7:	48 89 c7             	mov    %rax,%rdi
    14ca:	b8 00 00 00 00       	mov    $0x0,%eax
    14cf:	e8 fc fb ff ff       	call   10d0 <__isoc99_fscanf@plt>
    14d4:	83 f8 01             	cmp    $0x1,%eax
    14d7:	75 64                	jne    153d <main+0x28f>
    14d9:	48 8d 95 d8 06 ea ff 	lea    -0x15f928(%rbp),%rdx
    14e0:	48 8b 85 e8 06 ea ff 	mov    -0x15f918(%rbp),%rax
    14e7:	48 8d 0d 37 0b 00 00 	lea    0xb37(%rip),%rcx        # 2025 <_IO_stdin_used+0x25>
    14ee:	48 89 ce             	mov    %rcx,%rsi
    14f1:	48 89 c7             	mov    %rax,%rdi
    14f4:	b8 00 00 00 00       	mov    $0x0,%eax
    14f9:	e8 d2 fb ff ff       	call   10d0 <__isoc99_fscanf@plt>
    14fe:	83 f8 01             	cmp    $0x1,%eax
    1501:	75 3a                	jne    153d <main+0x28f>
    1503:	48 8d 95 dc 06 ea ff 	lea    -0x15f924(%rbp),%rdx
    150a:	48 8b 85 e8 06 ea ff 	mov    -0x15f918(%rbp),%rax
    1511:	48 8d 0d 0d 0b 00 00 	lea    0xb0d(%rip),%rcx        # 2025 <_IO_stdin_used+0x25>
    1518:	48 89 ce             	mov    %rcx,%rsi
    151b:	48 89 c7             	mov    %rax,%rdi
    151e:	b8 00 00 00 00       	mov    $0x0,%eax
    1523:	e8 a8 fb ff ff       	call   10d0 <__isoc99_fscanf@plt>
    1528:	83 f8 01             	cmp    $0x1,%eax
    152b:	75 10                	jne    153d <main+0x28f>
    152d:	81 bd e4 06 ea ff 5f 	cmpl   $0xea5f,-0x15f91c(%rbp)
    1534:	ea 00 00 
    1537:	0f 8e 21 fe ff ff    	jle    135e <main+0xb0>
    153d:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    1543:	89 c6                	mov    %eax,%esi
    1545:	48 8d 05 dc 0a 00 00 	lea    0xadc(%rip),%rax        # 2028 <_IO_stdin_used+0x28>
    154c:	48 89 c7             	mov    %rax,%rdi
    154f:	b8 00 00 00 00       	mov    $0x0,%eax
    1554:	e8 b7 fb ff ff       	call   1110 <printf@plt>
    1559:	8b 85 e4 06 ea ff    	mov    -0x15f91c(%rbp),%eax
    155f:	48 63 f0             	movslq %eax,%rsi
    1562:	48 8d 85 f0 06 ea ff 	lea    -0x15f910(%rbp),%rax
    1569:	48 8d 15 d9 fc ff ff 	lea    -0x327(%rip),%rdx        # 1249 <compare>
    1570:	48 89 d1             	mov    %rdx,%rcx
    1573:	ba 18 00 00 00       	mov    $0x18,%edx
    1578:	48 89 c7             	mov    %rax,%rdi
    157b:	e8 60 fb ff ff       	call   10e0 <qsort@plt>
    1580:	c7 85 e0 06 ea ff 00 	movl   $0x0,-0x15f920(%rbp)
    1587:	00 00 00 
    158a:	e9 80 00 00 00       	jmp    160f <main+0x361>
    158f:	8b 85 e0 06 ea ff    	mov    -0x15f920(%rbp),%eax
    1595:	48 63 d0             	movslq %eax,%rdx
    1598:	48 89 d0             	mov    %rdx,%rax
    159b:	48 01 c0             	add    %rax,%rax
    159e:	48 01 d0             	add    %rdx,%rax
    15a1:	48 c1 e0 03          	shl    $0x3,%rax
    15a5:	48 01 e8             	add    %rbp,%rax
    15a8:	48 2d 08 f9 15 00    	sub    $0x15f908,%rax
    15ae:	8b 08                	mov    (%rax),%ecx
    15b0:	8b 85 e0 06 ea ff    	mov    -0x15f920(%rbp),%eax
    15b6:	48 63 d0             	movslq %eax,%rdx
    15b9:	48 89 d0             	mov    %rdx,%rax
    15bc:	48 01 c0             	add    %rax,%rax
    15bf:	48 01 d0             	add    %rdx,%rax
    15c2:	48 c1 e0 03          	shl    $0x3,%rax
    15c6:	48 01 e8             	add    %rbp,%rax
    15c9:	48 2d 0c f9 15 00    	sub    $0x15f90c,%rax
    15cf:	8b 10                	mov    (%rax),%edx
    15d1:	8b 85 e0 06 ea ff    	mov    -0x15f920(%rbp),%eax
    15d7:	48 63 f0             	movslq %eax,%rsi
    15da:	48 89 f0             	mov    %rsi,%rax
    15dd:	48 01 c0             	add    %rax,%rax
    15e0:	48 01 f0             	add    %rsi,%rax
    15e3:	48 c1 e0 03          	shl    $0x3,%rax
    15e7:	48 01 e8             	add    %rbp,%rax
    15ea:	48 2d 10 f9 15 00    	sub    $0x15f910,%rax
    15f0:	8b 00                	mov    (%rax),%eax
    15f2:	89 c6                	mov    %eax,%esi
    15f4:	48 8d 05 66 0a 00 00 	lea    0xa66(%rip),%rax        # 2061 <_IO_stdin_used+0x61>
    15fb:	48 89 c7             	mov    %rax,%rdi
    15fe:	b8 00 00 00 00       	mov    $0x0,%eax
    1603:	e8 08 fb ff ff       	call   1110 <printf@plt>
    1608:	83 85 e0 06 ea ff 01 	addl   $0x1,-0x15f920(%rbp)
    160f:	8b 85 e0 06 ea ff    	mov    -0x15f920(%rbp),%eax
    1615:	3b 85 e4 06 ea ff    	cmp    -0x15f91c(%rbp),%eax
    161b:	0f 8c 6e ff ff ff    	jl     158f <main+0x2e1>
    1621:	b8 00 00 00 00       	mov    $0x0,%eax
    1626:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    162a:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    1631:	00 00 
    1633:	74 05                	je     163a <main+0x38c>
    1635:	e8 c6 fa ff ff       	call   1100 <__stack_chk_fail@plt>
    163a:	c9                   	leave  
    163b:	c3                   	ret    

Disassembly of section .fini:

000000000000163c <_fini>:
    163c:	f3 0f 1e fa          	endbr64 
    1640:	48 83 ec 08          	sub    $0x8,%rsp
    1644:	48 83 c4 08          	add    $0x8,%rsp
    1648:	c3                   	ret    
