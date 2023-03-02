
/usr/local/software/mibench/automotive/susan/susan:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 7f 00 00 	mov    0x7fd9(%rip),%rax        # 8fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 02 7f 00 00    	push   0x7f02(%rip)        # 8f28 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 03 7f 00 00 	bnd jmp *0x7f03(%rip)        # 8f30 <_GLOBAL_OFFSET_TABLE_+0x10>
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
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	push   $0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10df:	90                   	nop
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	68 0b 00 00 00       	push   $0xb
    10e9:	f2 e9 31 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10ef:	90                   	nop
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	68 0c 00 00 00       	push   $0xc
    10f9:	f2 e9 21 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10ff:	90                   	nop
    1100:	f3 0f 1e fa          	endbr64 
    1104:	68 0d 00 00 00       	push   $0xd
    1109:	f2 e9 11 ff ff ff    	bnd jmp 1020 <_init+0x20>
    110f:	90                   	nop
    1110:	f3 0f 1e fa          	endbr64 
    1114:	68 0e 00 00 00       	push   $0xe
    1119:	f2 e9 01 ff ff ff    	bnd jmp 1020 <_init+0x20>
    111f:	90                   	nop
    1120:	f3 0f 1e fa          	endbr64 
    1124:	68 0f 00 00 00       	push   $0xf
    1129:	f2 e9 f1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    112f:	90                   	nop
    1130:	f3 0f 1e fa          	endbr64 
    1134:	68 10 00 00 00       	push   $0x10
    1139:	f2 e9 e1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    113f:	90                   	nop
    1140:	f3 0f 1e fa          	endbr64 
    1144:	68 11 00 00 00       	push   $0x11
    1149:	f2 e9 d1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    114f:	90                   	nop
    1150:	f3 0f 1e fa          	endbr64 
    1154:	68 12 00 00 00       	push   $0x12
    1159:	f2 e9 c1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    115f:	90                   	nop
    1160:	f3 0f 1e fa          	endbr64 
    1164:	68 13 00 00 00       	push   $0x13
    1169:	f2 e9 b1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    116f:	90                   	nop

Disassembly of section .plt.got:

0000000000001170 <__cxa_finalize@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 7d 7e 00 00 	bnd jmp *0x7e7d(%rip)        # 8ff8 <__cxa_finalize@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001180 <free@plt>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	f2 ff 25 ad 7d 00 00 	bnd jmp *0x7dad(%rip)        # 8f38 <free@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001190 <puts@plt>:
    1190:	f3 0f 1e fa          	endbr64 
    1194:	f2 ff 25 a5 7d 00 00 	bnd jmp *0x7da5(%rip)        # 8f40 <puts@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011a0 <fread@plt>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	f2 ff 25 9d 7d 00 00 	bnd jmp *0x7d9d(%rip)        # 8f48 <fread@GLIBC_2.2.5>
    11ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011b0 <strtod@plt>:
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	f2 ff 25 95 7d 00 00 	bnd jmp *0x7d95(%rip)        # 8f50 <strtod@GLIBC_2.2.5>
    11bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011c0 <fclose@plt>:
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	f2 ff 25 8d 7d 00 00 	bnd jmp *0x7d8d(%rip)        # 8f58 <fclose@GLIBC_2.2.5>
    11cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011d0 <__stack_chk_fail@plt>:
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	f2 ff 25 85 7d 00 00 	bnd jmp *0x7d85(%rip)        # 8f60 <__stack_chk_fail@GLIBC_2.4>
    11db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011e0 <memset@plt>:
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	f2 ff 25 7d 7d 00 00 	bnd jmp *0x7d7d(%rip)        # 8f68 <memset@GLIBC_2.2.5>
    11eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000011f0 <fgetc@plt>:
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	f2 ff 25 75 7d 00 00 	bnd jmp *0x7d75(%rip)        # 8f70 <fgetc@GLIBC_2.2.5>
    11fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001200 <fgets@plt>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	f2 ff 25 6d 7d 00 00 	bnd jmp *0x7d6d(%rip)        # 8f78 <fgets@GLIBC_2.2.5>
    120b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001210 <strtol@plt>:
    1210:	f3 0f 1e fa          	endbr64 
    1214:	f2 ff 25 65 7d 00 00 	bnd jmp *0x7d65(%rip)        # 8f80 <strtol@GLIBC_2.2.5>
    121b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001220 <memcpy@plt>:
    1220:	f3 0f 1e fa          	endbr64 
    1224:	f2 ff 25 5d 7d 00 00 	bnd jmp *0x7d5d(%rip)        # 8f88 <memcpy@GLIBC_2.14>
    122b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001230 <sqrtf@plt>:
    1230:	f3 0f 1e fa          	endbr64 
    1234:	f2 ff 25 55 7d 00 00 	bnd jmp *0x7d55(%rip)        # 8f90 <sqrtf@GLIBC_2.2.5>
    123b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001240 <malloc@plt>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	f2 ff 25 4d 7d 00 00 	bnd jmp *0x7d4d(%rip)        # 8f98 <malloc@GLIBC_2.2.5>
    124b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001250 <__printf_chk@plt>:
    1250:	f3 0f 1e fa          	endbr64 
    1254:	f2 ff 25 45 7d 00 00 	bnd jmp *0x7d45(%rip)        # 8fa0 <__printf_chk@GLIBC_2.3.4>
    125b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001260 <fopen@plt>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	f2 ff 25 3d 7d 00 00 	bnd jmp *0x7d3d(%rip)        # 8fa8 <fopen@GLIBC_2.2.5>
    126b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001270 <exit@plt>:
    1270:	f3 0f 1e fa          	endbr64 
    1274:	f2 ff 25 35 7d 00 00 	bnd jmp *0x7d35(%rip)        # 8fb0 <exit@GLIBC_2.2.5>
    127b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001280 <fwrite@plt>:
    1280:	f3 0f 1e fa          	endbr64 
    1284:	f2 ff 25 2d 7d 00 00 	bnd jmp *0x7d2d(%rip)        # 8fb8 <fwrite@GLIBC_2.2.5>
    128b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001290 <__fprintf_chk@plt>:
    1290:	f3 0f 1e fa          	endbr64 
    1294:	f2 ff 25 25 7d 00 00 	bnd jmp *0x7d25(%rip)        # 8fc0 <__fprintf_chk@GLIBC_2.3.4>
    129b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012a0 <getc@plt>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	f2 ff 25 1d 7d 00 00 	bnd jmp *0x7d1d(%rip)        # 8fc8 <getc@GLIBC_2.2.5>
    12ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000012b0 <exp@plt>:
    12b0:	f3 0f 1e fa          	endbr64 
    12b4:	f2 ff 25 15 7d 00 00 	bnd jmp *0x7d15(%rip)        # 8fd0 <exp@GLIBC_2.29>
    12bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

00000000000012c0 <main>:
    12c0:	f3 0f 1e fa          	endbr64 
    12c4:	41 57                	push   %r15
    12c6:	41 56                	push   %r14
    12c8:	41 55                	push   %r13
    12ca:	41 54                	push   %r12
    12cc:	55                   	push   %rbp
    12cd:	53                   	push   %rbx
    12ce:	4c 8d 9c 24 00 90 fa 	lea    -0x57000(%rsp),%r11
    12d5:	ff 
    12d6:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    12dd:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    12e2:	4c 39 dc             	cmp    %r11,%rsp
    12e5:	75 ef                	jne    12d6 <main+0x16>
    12e7:	48 81 ec 98 0e 00 00 	sub    $0xe98,%rsp
    12ee:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    12f5:	00 00 
    12f7:	48 89 84 24 88 7e 05 	mov    %rax,0x57e88(%rsp)
    12fe:	00 
    12ff:	31 c0                	xor    %eax,%eax
    1301:	83 ff 02             	cmp    $0x2,%edi
    1304:	0f 8e 68 05 00 00    	jle    1872 <main+0x5b2>
    130a:	49 89 f7             	mov    %rsi,%r15
    130d:	41 89 fd             	mov    %edi,%r13d
    1310:	48 8d 4c 24 2c       	lea    0x2c(%rsp),%rcx
    1315:	31 c0                	xor    %eax,%eax
    1317:	49 8b 7f 08          	mov    0x8(%r15),%rdi
    131b:	48 8d 54 24 28       	lea    0x28(%rsp),%rdx
    1320:	48 8d 74 24 30       	lea    0x30(%rsp),%rsi
    1325:	e8 f6 07 00 00       	call   1b20 <get_image>
    132a:	41 83 fd 03          	cmp    $0x3,%r13d
    132e:	0f 84 17 04 00 00    	je     174b <main+0x48b>
    1334:	c7 44 24 1c 00 00 00 	movl   $0x0,0x1c(%rsp)
    133b:	00 
    133c:	31 db                	xor    %ebx,%ebx
    133e:	45 31 e4             	xor    %r12d,%r12d
    1341:	f3 0f 10 05 7f 63 00 	movss  0x637f(%rip),%xmm0        # 76c8 <_IO_stdin_used+0x6c8>
    1348:	00 
    1349:	c7 44 24 14 00 00 00 	movl   $0x0,0x14(%rsp)
    1350:	00 
    1351:	b8 03 00 00 00       	mov    $0x3,%eax
    1356:	4c 8d 35 0b 62 00 00 	lea    0x620b(%rip),%r14        # 7568 <_IO_stdin_used+0x568>
    135d:	c7 44 24 18 01 00 00 	movl   $0x1,0x18(%rsp)
    1364:	00 
    1365:	c7 44 24 0c 00 00 00 	movl   $0x0,0xc(%rsp)
    136c:	00 
    136d:	c7 44 24 10 14 00 00 	movl   $0x14,0x10(%rsp)
    1374:	00 
    1375:	0f 1f 00             	nopl   (%rax)
    1378:	48 63 c8             	movslq %eax,%rcx
    137b:	49 8b 34 cf          	mov    (%r15,%rcx,8),%rsi
    137f:	48 8d 14 cd 00 00 00 	lea    0x0(,%rcx,8),%rdx
    1386:	00 
    1387:	80 3e 2d             	cmpb   $0x2d,(%rsi)
    138a:	0f 85 e2 04 00 00    	jne    1872 <main+0x5b2>
    1390:	8d 68 01             	lea    0x1(%rax),%ebp
    1393:	0f b6 46 01          	movzbl 0x1(%rsi),%eax
    1397:	83 e8 33             	sub    $0x33,%eax
    139a:	3c 41                	cmp    $0x41,%al
    139c:	77 22                	ja     13c0 <main+0x100>
    139e:	0f b6 c0             	movzbl %al,%eax
    13a1:	49 63 04 86          	movslq (%r14,%rax,4),%rax
    13a5:	4c 01 f0             	add    %r14,%rax
    13a8:	3e ff e0             	notrack jmp *%rax
    13ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    13b0:	c7 44 24 1c 01 00 00 	movl   $0x1,0x1c(%rsp)
    13b7:	00 
    13b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    13bf:	00 
    13c0:	89 e8                	mov    %ebp,%eax
    13c2:	41 39 ed             	cmp    %ebp,%r13d
    13c5:	7f b1                	jg     1378 <main+0xb8>
    13c7:	85 db                	test   %ebx,%ebx
    13c9:	0f 85 a6 01 00 00    	jne    1575 <main+0x2b5>
    13cf:	83 7c 24 0c 00       	cmpl   $0x0,0xc(%rsp)
    13d4:	0f 84 9b 01 00 00    	je     1575 <main+0x2b5>
    13da:	8b 7c 24 28          	mov    0x28(%rsp),%edi
    13de:	0f af 7c 24 2c       	imul   0x2c(%rsp),%edi
    13e3:	48 63 ff             	movslq %edi,%rdi
    13e6:	48 c1 e7 02          	shl    $0x2,%rdi
    13ea:	e8 51 fe ff ff       	call   1240 <malloc@plt>
    13ef:	8b 74 24 10          	mov    0x10(%rsp),%esi
    13f3:	48 8d 7c 24 38       	lea    0x38(%rsp),%rdi
    13f8:	ba 06 00 00 00       	mov    $0x6,%edx
    13fd:	48 89 c3             	mov    %rax,%rbx
    1400:	31 c0                	xor    %eax,%eax
    1402:	e8 b9 0a 00 00       	call   1ec0 <setup_brightness_lut>
    1407:	48 8b 6c 24 30       	mov    0x30(%rsp),%rbp
    140c:	44 8b 4c 24 2c       	mov    0x2c(%rsp),%r9d
    1411:	48 89 de             	mov    %rbx,%rsi
    1414:	31 c0                	xor    %eax,%eax
    1416:	44 8b 44 24 28       	mov    0x28(%rsp),%r8d
    141b:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
    1420:	b9 5a 0a 00 00       	mov    $0xa5a,%ecx
    1425:	48 89 ef             	mov    %rbp,%rdi
    1428:	45 85 e4             	test   %r12d,%r12d
    142b:	0f 85 76 03 00 00    	jne    17a7 <main+0x4e7>
    1431:	e8 8a 0b 00 00       	call   1fc0 <susan_principle>
    1436:	8b 54 24 28          	mov    0x28(%rsp),%edx
    143a:	0f af 54 24 2c       	imul   0x2c(%rsp),%edx
    143f:	48 89 ee             	mov    %rbp,%rsi
    1442:	48 89 df             	mov    %rbx,%rdi
    1445:	31 c0                	xor    %eax,%eax
    1447:	e8 e4 08 00 00       	call   1d30 <int_to_uchar>
    144c:	e9 b7 02 00 00       	jmp    1708 <main+0x448>
    1451:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1458:	41 39 ed             	cmp    %ebp,%r13d
    145b:	0f 8e 50 03 00 00    	jle    17b1 <main+0x4f1>
    1461:	49 8b 7c 17 08       	mov    0x8(%r15,%rdx,1),%rdi
    1466:	31 f6                	xor    %esi,%esi
    1468:	ba 0a 00 00 00       	mov    $0xa,%edx
    146d:	83 c5 01             	add    $0x1,%ebp
    1470:	f3 0f 11 44 24 08    	movss  %xmm0,0x8(%rsp)
    1476:	e8 95 fd ff ff       	call   1210 <strtol@plt>
    147b:	f3 0f 10 44 24 08    	movss  0x8(%rsp),%xmm0
    1481:	89 44 24 10          	mov    %eax,0x10(%rsp)
    1485:	89 e8                	mov    %ebp,%eax
    1487:	41 39 ed             	cmp    %ebp,%r13d
    148a:	0f 8f e8 fe ff ff    	jg     1378 <main+0xb8>
    1490:	e9 32 ff ff ff       	jmp    13c7 <main+0x107>
    1495:	0f 1f 00             	nopl   (%rax)
    1498:	c7 44 24 0c 01 00 00 	movl   $0x1,0xc(%rsp)
    149f:	00 
    14a0:	89 e8                	mov    %ebp,%eax
    14a2:	41 39 ed             	cmp    %ebp,%r13d
    14a5:	0f 8f cd fe ff ff    	jg     1378 <main+0xb8>
    14ab:	e9 17 ff ff ff       	jmp    13c7 <main+0x107>
    14b0:	c7 44 24 18 00 00 00 	movl   $0x0,0x18(%rsp)
    14b7:	00 
    14b8:	89 e8                	mov    %ebp,%eax
    14ba:	41 39 ed             	cmp    %ebp,%r13d
    14bd:	0f 8f b5 fe ff ff    	jg     1378 <main+0xb8>
    14c3:	e9 ff fe ff ff       	jmp    13c7 <main+0x107>
    14c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    14cf:	00 
    14d0:	41 39 ed             	cmp    %ebp,%r13d
    14d3:	0f 8e eb 02 00 00    	jle    17c4 <main+0x504>
    14d9:	49 8b 7c 17 08       	mov    0x8(%r15,%rdx,1),%rdi
    14de:	31 f6                	xor    %esi,%esi
    14e0:	e8 cb fc ff ff       	call   11b0 <strtod@plt>
    14e5:	66 0f ef c9          	pxor   %xmm1,%xmm1
    14e9:	f2 0f 5a c0          	cvtsd2ss %xmm0,%xmm0
    14ed:	0f 2f c8             	comiss %xmm0,%xmm1
    14f0:	0f 87 22 01 00 00    	ja     1618 <main+0x358>
    14f6:	83 c5 01             	add    $0x1,%ebp
    14f9:	89 e8                	mov    %ebp,%eax
    14fb:	41 39 ed             	cmp    %ebp,%r13d
    14fe:	0f 8f 74 fe ff ff    	jg     1378 <main+0xb8>
    1504:	e9 be fe ff ff       	jmp    13c7 <main+0x107>
    1509:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1510:	bb 02 00 00 00       	mov    $0x2,%ebx
    1515:	89 e8                	mov    %ebp,%eax
    1517:	41 39 ed             	cmp    %ebp,%r13d
    151a:	0f 8f 58 fe ff ff    	jg     1378 <main+0xb8>
    1520:	e9 a2 fe ff ff       	jmp    13c7 <main+0x107>
    1525:	0f 1f 00             	nopl   (%rax)
    1528:	c7 44 24 14 01 00 00 	movl   $0x1,0x14(%rsp)
    152f:	00 
    1530:	89 e8                	mov    %ebp,%eax
    1532:	41 39 ed             	cmp    %ebp,%r13d
    1535:	0f 8f 3d fe ff ff    	jg     1378 <main+0xb8>
    153b:	e9 87 fe ff ff       	jmp    13c7 <main+0x107>
    1540:	41 bc 01 00 00 00    	mov    $0x1,%r12d
    1546:	89 e8                	mov    %ebp,%eax
    1548:	41 39 ed             	cmp    %ebp,%r13d
    154b:	0f 8f 27 fe ff ff    	jg     1378 <main+0xb8>
    1551:	e9 71 fe ff ff       	jmp    13c7 <main+0x107>
    1556:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    155d:	00 00 00 
    1560:	bb 01 00 00 00       	mov    $0x1,%ebx
    1565:	89 e8                	mov    %ebp,%eax
    1567:	41 39 ed             	cmp    %ebp,%r13d
    156a:	0f 8f 08 fe ff ff    	jg     1378 <main+0xb8>
    1570:	e9 52 fe ff ff       	jmp    13c7 <main+0x107>
    1575:	83 fb 01             	cmp    $0x1,%ebx
    1578:	0f 84 ba 00 00 00    	je     1638 <main+0x378>
    157e:	83 fb 02             	cmp    $0x2,%ebx
    1581:	0f 85 d7 01 00 00    	jne    175e <main+0x49e>
    1587:	8b 7c 24 28          	mov    0x28(%rsp),%edi
    158b:	0f af 7c 24 2c       	imul   0x2c(%rsp),%edi
    1590:	48 63 ff             	movslq %edi,%rdi
    1593:	48 c1 e7 02          	shl    $0x2,%rdi
    1597:	e8 a4 fc ff ff       	call   1240 <malloc@plt>
    159c:	8b 74 24 10          	mov    0x10(%rsp),%esi
    15a0:	48 8d 7c 24 38       	lea    0x38(%rsp),%rdi
    15a5:	ba 06 00 00 00       	mov    $0x6,%edx
    15aa:	49 89 c4             	mov    %rax,%r12
    15ad:	31 c0                	xor    %eax,%eax
    15af:	e8 0c 09 00 00       	call   1ec0 <setup_brightness_lut>
    15b4:	83 7c 24 0c 00       	cmpl   $0x0,0xc(%rsp)
    15b9:	0f 85 58 02 00 00    	jne    1817 <main+0x557>
    15bf:	83 7c 24 1c 00       	cmpl   $0x0,0x1c(%rsp)
    15c4:	8b 44 24 2c          	mov    0x2c(%rsp),%eax
    15c8:	48 8d 6c 24 40       	lea    0x40(%rsp),%rbp
    15cd:	44 8b 4c 24 28       	mov    0x28(%rsp),%r9d
    15d2:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
    15d7:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    15dc:	0f 85 17 02 00 00    	jne    17f9 <main+0x539>
    15e2:	51                   	push   %rcx
    15e3:	4c 89 e6             	mov    %r12,%rsi
    15e6:	49 89 e8             	mov    %rbp,%r8
    15e9:	b9 3a 07 00 00       	mov    $0x73a,%ecx
    15ee:	50                   	push   %rax
    15ef:	31 c0                	xor    %eax,%eax
    15f1:	e8 6a 3b 00 00       	call   5160 <susan_corners>
    15f6:	5e                   	pop    %rsi
    15f7:	5f                   	pop    %rdi
    15f8:	8b 4c 24 14          	mov    0x14(%rsp),%ecx
    15fc:	8b 54 24 28          	mov    0x28(%rsp),%edx
    1600:	48 89 ee             	mov    %rbp,%rsi
    1603:	31 c0                	xor    %eax,%eax
    1605:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    160a:	e8 71 3a 00 00       	call   5080 <corner_draw>
    160f:	e9 f4 00 00 00       	jmp    1708 <main+0x448>
    1614:	0f 1f 40 00          	nopl   0x0(%rax)
    1618:	83 c5 01             	add    $0x1,%ebp
    161b:	41 bc 01 00 00 00    	mov    $0x1,%r12d
    1621:	89 e8                	mov    %ebp,%eax
    1623:	41 39 ed             	cmp    %ebp,%r13d
    1626:	0f 8f 4c fd ff ff    	jg     1378 <main+0xb8>
    162c:	e9 96 fd ff ff       	jmp    13c7 <main+0x107>
    1631:	31 db                	xor    %ebx,%ebx
    1633:	e9 88 fd ff ff       	jmp    13c0 <main+0x100>
    1638:	8b 7c 24 28          	mov    0x28(%rsp),%edi
    163c:	0f af 7c 24 2c       	imul   0x2c(%rsp),%edi
    1641:	48 63 ff             	movslq %edi,%rdi
    1644:	48 c1 e7 02          	shl    $0x2,%rdi
    1648:	e8 f3 fb ff ff       	call   1240 <malloc@plt>
    164d:	8b 74 24 10          	mov    0x10(%rsp),%esi
    1651:	48 8d 7c 24 38       	lea    0x38(%rsp),%rdi
    1656:	ba 06 00 00 00       	mov    $0x6,%edx
    165b:	48 89 c3             	mov    %rax,%rbx
    165e:	31 c0                	xor    %eax,%eax
    1660:	e8 5b 08 00 00       	call   1ec0 <setup_brightness_lut>
    1665:	83 7c 24 0c 00       	cmpl   $0x0,0xc(%rsp)
    166a:	0f 85 97 fd ff ff    	jne    1407 <main+0x147>
    1670:	44 8b 4c 24 28       	mov    0x28(%rsp),%r9d
    1675:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
    1679:	45 89 cd             	mov    %r9d,%r13d
    167c:	44 89 4c 24 0c       	mov    %r9d,0xc(%rsp)
    1681:	44 0f af e9          	imul   %ecx,%r13d
    1685:	89 4c 24 08          	mov    %ecx,0x8(%rsp)
    1689:	4d 63 ed             	movslq %r13d,%r13
    168c:	4c 89 ef             	mov    %r13,%rdi
    168f:	e8 ac fb ff ff       	call   1240 <malloc@plt>
    1694:	4c 89 ea             	mov    %r13,%rdx
    1697:	be 64 00 00 00       	mov    $0x64,%esi
    169c:	48 89 c7             	mov    %rax,%rdi
    169f:	48 89 c5             	mov    %rax,%rbp
    16a2:	e8 39 fb ff ff       	call   11e0 <memset@plt>
    16a7:	45 85 e4             	test   %r12d,%r12d
    16aa:	4c 8b 5c 24 38       	mov    0x38(%rsp),%r11
    16af:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    16b4:	8b 4c 24 08          	mov    0x8(%rsp),%ecx
    16b8:	44 8b 4c 24 0c       	mov    0xc(%rsp),%r9d
    16bd:	0f 84 14 01 00 00    	je     17d7 <main+0x517>
    16c3:	50                   	push   %rax
    16c4:	48 89 ea             	mov    %rbp,%rdx
    16c7:	41 b8 5a 0a 00 00    	mov    $0xa5a,%r8d
    16cd:	48 89 de             	mov    %rbx,%rsi
    16d0:	51                   	push   %rcx
    16d1:	31 c0                	xor    %eax,%eax
    16d3:	4c 89 d9             	mov    %r11,%rcx
    16d6:	e8 35 33 00 00       	call   4a10 <susan_edges_small>
    16db:	58                   	pop    %rax
    16dc:	5a                   	pop    %rdx
    16dd:	83 7c 24 18 00       	cmpl   $0x0,0x18(%rsp)
    16e2:	0f 85 70 01 00 00    	jne    1858 <main+0x598>
    16e8:	44 8b 44 24 14       	mov    0x14(%rsp),%r8d
    16ed:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
    16f1:	48 89 ee             	mov    %rbp,%rsi
    16f4:	31 c0                	xor    %eax,%eax
    16f6:	8b 54 24 28          	mov    0x28(%rsp),%edx
    16fa:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    16ff:	e8 3c 18 00 00       	call   2f40 <edge_draw>
    1704:	0f 1f 40 00          	nopl   0x0(%rax)
    1708:	49 8b 7f 10          	mov    0x10(%r15),%rdi
    170c:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
    1710:	31 c0                	xor    %eax,%eax
    1712:	8b 54 24 28          	mov    0x28(%rsp),%edx
    1716:	48 8b 74 24 30       	mov    0x30(%rsp),%rsi
    171b:	e8 30 05 00 00       	call   1c50 <put_image>
    1720:	48 8b 84 24 88 7e 05 	mov    0x57e88(%rsp),%rax
    1727:	00 
    1728:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    172f:	00 00 
    1731:	0f 85 42 01 00 00    	jne    1879 <main+0x5b9>
    1737:	48 81 c4 98 7e 05 00 	add    $0x57e98,%rsp
    173e:	31 c0                	xor    %eax,%eax
    1740:	5b                   	pop    %rbx
    1741:	5d                   	pop    %rbp
    1742:	41 5c                	pop    %r12
    1744:	41 5d                	pop    %r13
    1746:	41 5e                	pop    %r14
    1748:	41 5f                	pop    %r15
    174a:	c3                   	ret    
    174b:	c7 44 24 10 14 00 00 	movl   $0x14,0x10(%rsp)
    1752:	00 
    1753:	f3 0f 10 05 6d 5f 00 	movss  0x5f6d(%rip),%xmm0        # 76c8 <_IO_stdin_used+0x6c8>
    175a:	00 
    175b:	45 31 e4             	xor    %r12d,%r12d
    175e:	8b 74 24 10          	mov    0x10(%rsp),%esi
    1762:	48 8d 7c 24 38       	lea    0x38(%rsp),%rdi
    1767:	31 c0                	xor    %eax,%eax
    1769:	ba 02 00 00 00       	mov    $0x2,%edx
    176e:	f3 0f 11 44 24 08    	movss  %xmm0,0x8(%rsp)
    1774:	e8 47 07 00 00       	call   1ec0 <setup_brightness_lut>
    1779:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
    177d:	8b 54 24 28          	mov    0x28(%rsp),%edx
    1781:	44 89 e7             	mov    %r12d,%edi
    1784:	f3 0f 10 44 24 08    	movss  0x8(%rsp),%xmm0
    178a:	4c 8b 44 24 38       	mov    0x38(%rsp),%r8
    178f:	b8 01 00 00 00       	mov    $0x1,%eax
    1794:	48 8b 74 24 30       	mov    0x30(%rsp),%rsi
    1799:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    179d:	e8 1e 11 00 00       	call   28c0 <susan_smoothing>
    17a2:	e9 61 ff ff ff       	jmp    1708 <main+0x448>
    17a7:	e8 14 0c 00 00       	call   23c0 <susan_principle_small>
    17ac:	e9 85 fc ff ff       	jmp    1436 <main+0x176>
    17b1:	48 8d 3d 95 5d 00 00 	lea    0x5d95(%rip),%rdi        # 754d <_IO_stdin_used+0x54d>
    17b8:	e8 d3 f9 ff ff       	call   1190 <puts@plt>
    17bd:	31 ff                	xor    %edi,%edi
    17bf:	e8 ac fa ff ff       	call   1270 <exit@plt>
    17c4:	48 8d 3d 69 5d 00 00 	lea    0x5d69(%rip),%rdi        # 7534 <_IO_stdin_used+0x534>
    17cb:	e8 c0 f9 ff ff       	call   1190 <puts@plt>
    17d0:	31 ff                	xor    %edi,%edi
    17d2:	e8 99 fa ff ff       	call   1270 <exit@plt>
    17d7:	41 54                	push   %r12
    17d9:	41 b8 5a 0a 00 00    	mov    $0xa5a,%r8d
    17df:	48 89 ea             	mov    %rbp,%rdx
    17e2:	48 89 de             	mov    %rbx,%rsi
    17e5:	51                   	push   %rcx
    17e6:	31 c0                	xor    %eax,%eax
    17e8:	4c 89 d9             	mov    %r11,%rcx
    17eb:	e8 70 20 00 00       	call   3860 <susan_edges>
    17f0:	41 5d                	pop    %r13
    17f2:	41 5e                	pop    %r14
    17f4:	e9 e4 fe ff ff       	jmp    16dd <main+0x41d>
    17f9:	41 50                	push   %r8
    17fb:	b9 3a 07 00 00       	mov    $0x73a,%ecx
    1800:	49 89 e8             	mov    %rbp,%r8
    1803:	4c 89 e6             	mov    %r12,%rsi
    1806:	50                   	push   %rax
    1807:	31 c0                	xor    %eax,%eax
    1809:	e8 72 48 00 00       	call   6080 <susan_corners_quick>
    180e:	41 59                	pop    %r9
    1810:	41 5a                	pop    %r10
    1812:	e9 e1 fd ff ff       	jmp    15f8 <main+0x338>
    1817:	48 8b 6c 24 30       	mov    0x30(%rsp),%rbp
    181c:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
    1821:	4c 89 e6             	mov    %r12,%rsi
    1824:	31 c0                	xor    %eax,%eax
    1826:	44 8b 4c 24 2c       	mov    0x2c(%rsp),%r9d
    182b:	44 8b 44 24 28       	mov    0x28(%rsp),%r8d
    1830:	b9 3a 07 00 00       	mov    $0x73a,%ecx
    1835:	48 89 ef             	mov    %rbp,%rdi
    1838:	e8 83 07 00 00       	call   1fc0 <susan_principle>
    183d:	8b 54 24 28          	mov    0x28(%rsp),%edx
    1841:	0f af 54 24 2c       	imul   0x2c(%rsp),%edx
    1846:	31 c0                	xor    %eax,%eax
    1848:	48 89 ee             	mov    %rbp,%rsi
    184b:	4c 89 e7             	mov    %r12,%rdi
    184e:	e8 dd 04 00 00       	call   1d30 <int_to_uchar>
    1853:	e9 b0 fe ff ff       	jmp    1708 <main+0x448>
    1858:	8b 4c 24 2c          	mov    0x2c(%rsp),%ecx
    185c:	8b 54 24 28          	mov    0x28(%rsp),%edx
    1860:	48 89 ee             	mov    %rbp,%rsi
    1863:	48 89 df             	mov    %rbx,%rdi
    1866:	31 c0                	xor    %eax,%eax
    1868:	e8 83 17 00 00       	call   2ff0 <susan_thin>
    186d:	e9 76 fe ff ff       	jmp    16e8 <main+0x428>
    1872:	31 c0                	xor    %eax,%eax
    1874:	e8 f7 00 00 00       	call   1970 <usage>
    1879:	e8 52 f9 ff ff       	call   11d0 <__stack_chk_fail@plt>
    187e:	66 90                	xchg   %ax,%ax

0000000000001880 <_start>:
    1880:	f3 0f 1e fa          	endbr64 
    1884:	31 ed                	xor    %ebp,%ebp
    1886:	49 89 d1             	mov    %rdx,%r9
    1889:	5e                   	pop    %rsi
    188a:	48 89 e2             	mov    %rsp,%rdx
    188d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1891:	50                   	push   %rax
    1892:	54                   	push   %rsp
    1893:	45 31 c0             	xor    %r8d,%r8d
    1896:	31 c9                	xor    %ecx,%ecx
    1898:	48 8d 3d 21 fa ff ff 	lea    -0x5df(%rip),%rdi        # 12c0 <main>
    189f:	ff 15 33 77 00 00    	call   *0x7733(%rip)        # 8fd8 <__libc_start_main@GLIBC_2.34>
    18a5:	f4                   	hlt    
    18a6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    18ad:	00 00 00 

00000000000018b0 <deregister_tm_clones>:
    18b0:	48 8d 3d 59 77 00 00 	lea    0x7759(%rip),%rdi        # 9010 <__TMC_END__>
    18b7:	48 8d 05 52 77 00 00 	lea    0x7752(%rip),%rax        # 9010 <__TMC_END__>
    18be:	48 39 f8             	cmp    %rdi,%rax
    18c1:	74 15                	je     18d8 <deregister_tm_clones+0x28>
    18c3:	48 8b 05 16 77 00 00 	mov    0x7716(%rip),%rax        # 8fe0 <_ITM_deregisterTMCloneTable@Base>
    18ca:	48 85 c0             	test   %rax,%rax
    18cd:	74 09                	je     18d8 <deregister_tm_clones+0x28>
    18cf:	ff e0                	jmp    *%rax
    18d1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    18d8:	c3                   	ret    
    18d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000018e0 <register_tm_clones>:
    18e0:	48 8d 3d 29 77 00 00 	lea    0x7729(%rip),%rdi        # 9010 <__TMC_END__>
    18e7:	48 8d 35 22 77 00 00 	lea    0x7722(%rip),%rsi        # 9010 <__TMC_END__>
    18ee:	48 29 fe             	sub    %rdi,%rsi
    18f1:	48 89 f0             	mov    %rsi,%rax
    18f4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    18f8:	48 c1 f8 03          	sar    $0x3,%rax
    18fc:	48 01 c6             	add    %rax,%rsi
    18ff:	48 d1 fe             	sar    %rsi
    1902:	74 14                	je     1918 <register_tm_clones+0x38>
    1904:	48 8b 05 e5 76 00 00 	mov    0x76e5(%rip),%rax        # 8ff0 <_ITM_registerTMCloneTable@Base>
    190b:	48 85 c0             	test   %rax,%rax
    190e:	74 08                	je     1918 <register_tm_clones+0x38>
    1910:	ff e0                	jmp    *%rax
    1912:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1918:	c3                   	ret    
    1919:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001920 <__do_global_dtors_aux>:
    1920:	f3 0f 1e fa          	endbr64 
    1924:	80 3d fd 76 00 00 00 	cmpb   $0x0,0x76fd(%rip)        # 9028 <completed.0>
    192b:	75 2b                	jne    1958 <__do_global_dtors_aux+0x38>
    192d:	55                   	push   %rbp
    192e:	48 83 3d c2 76 00 00 	cmpq   $0x0,0x76c2(%rip)        # 8ff8 <__cxa_finalize@GLIBC_2.2.5>
    1935:	00 
    1936:	48 89 e5             	mov    %rsp,%rbp
    1939:	74 0c                	je     1947 <__do_global_dtors_aux+0x27>
    193b:	48 8b 3d c6 76 00 00 	mov    0x76c6(%rip),%rdi        # 9008 <__dso_handle>
    1942:	e8 29 f8 ff ff       	call   1170 <__cxa_finalize@plt>
    1947:	e8 64 ff ff ff       	call   18b0 <deregister_tm_clones>
    194c:	c6 05 d5 76 00 00 01 	movb   $0x1,0x76d5(%rip)        # 9028 <completed.0>
    1953:	5d                   	pop    %rbp
    1954:	c3                   	ret    
    1955:	0f 1f 00             	nopl   (%rax)
    1958:	c3                   	ret    
    1959:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001960 <frame_dummy>:
    1960:	f3 0f 1e fa          	endbr64 
    1964:	e9 77 ff ff ff       	jmp    18e0 <register_tm_clones>
    1969:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001970 <usage>:
    1970:	f3 0f 1e fa          	endbr64 
    1974:	50                   	push   %rax
    1975:	58                   	pop    %rax
    1976:	48 8d 3d 8b 56 00 00 	lea    0x568b(%rip),%rdi        # 7008 <_IO_stdin_used+0x8>
    197d:	48 83 ec 08          	sub    $0x8,%rsp
    1981:	e8 0a f8 ff ff       	call   1190 <puts@plt>
    1986:	48 8d 3d c4 5a 00 00 	lea    0x5ac4(%rip),%rdi        # 7451 <_IO_stdin_used+0x451>
    198d:	e8 fe f7 ff ff       	call   1190 <puts@plt>
    1992:	48 8d 3d d6 5a 00 00 	lea    0x5ad6(%rip),%rdi        # 746f <_IO_stdin_used+0x46f>
    1999:	e8 f2 f7 ff ff       	call   1190 <puts@plt>
    199e:	48 8d 3d da 5a 00 00 	lea    0x5ada(%rip),%rdi        # 747f <_IO_stdin_used+0x47f>
    19a5:	e8 e6 f7 ff ff       	call   1190 <puts@plt>
    19aa:	48 8d 3d 87 56 00 00 	lea    0x5687(%rip),%rdi        # 7038 <_IO_stdin_used+0x38>
    19b1:	e8 da f7 ff ff       	call   1190 <puts@plt>
    19b6:	48 8d 3d c3 56 00 00 	lea    0x56c3(%rip),%rdi        # 7080 <_IO_stdin_used+0x80>
    19bd:	e8 ce f7 ff ff       	call   1190 <puts@plt>
    19c2:	48 8d 3d f7 56 00 00 	lea    0x56f7(%rip),%rdi        # 70c0 <_IO_stdin_used+0xc0>
    19c9:	e8 c2 f7 ff ff       	call   1190 <puts@plt>
    19ce:	48 8d 3d 5b 57 00 00 	lea    0x575b(%rip),%rdi        # 7130 <_IO_stdin_used+0x130>
    19d5:	e8 b6 f7 ff ff       	call   1190 <puts@plt>
    19da:	48 8d 3d 7f 57 00 00 	lea    0x577f(%rip),%rdi        # 7160 <_IO_stdin_used+0x160>
    19e1:	e8 aa f7 ff ff       	call   1190 <puts@plt>
    19e6:	48 8d 3d c3 57 00 00 	lea    0x57c3(%rip),%rdi        # 71b0 <_IO_stdin_used+0x1b0>
    19ed:	e8 9e f7 ff ff       	call   1190 <puts@plt>
    19f2:	48 8d 3d 27 58 00 00 	lea    0x5827(%rip),%rdi        # 7220 <_IO_stdin_used+0x220>
    19f9:	e8 92 f7 ff ff       	call   1190 <puts@plt>
    19fe:	48 8d 3d 8b 58 00 00 	lea    0x588b(%rip),%rdi        # 7290 <_IO_stdin_used+0x290>
    1a05:	e8 86 f7 ff ff       	call   1190 <puts@plt>
    1a0a:	48 8d 3d df 58 00 00 	lea    0x58df(%rip),%rdi        # 72f0 <_IO_stdin_used+0x2f0>
    1a11:	e8 7a f7 ff ff       	call   1190 <puts@plt>
    1a16:	31 ff                	xor    %edi,%edi
    1a18:	e8 53 f8 ff ff       	call   1270 <exit@plt>
    1a1d:	0f 1f 00             	nopl   (%rax)

0000000000001a20 <getint>:
    1a20:	f3 0f 1e fa          	endbr64 
    1a24:	41 54                	push   %r12
    1a26:	53                   	push   %rbx
    1a27:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    1a2e:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    1a33:	48 81 ec 00 10 00 00 	sub    $0x1000,%rsp
    1a3a:	48 83 0c 24 00       	orq    $0x0,(%rsp)
    1a3f:	48 81 ec 28 07 00 00 	sub    $0x728,%rsp
    1a46:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    1a4d:	00 00 
    1a4f:	48 89 84 24 18 27 00 	mov    %rax,0x2718(%rsp)
    1a56:	00 
    1a57:	31 c0                	xor    %eax,%eax
    1a59:	48 89 fb             	mov    %rdi,%rbx
    1a5c:	49 89 e4             	mov    %rsp,%r12
    1a5f:	e8 3c f8 ff ff       	call   12a0 <getc@plt>
    1a64:	eb 1f                	jmp    1a85 <getint+0x65>
    1a66:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    1a6d:	00 00 00 
    1a70:	83 f8 ff             	cmp    $0xffffffff,%eax
    1a73:	74 2b                	je     1aa0 <getint+0x80>
    1a75:	83 e8 30             	sub    $0x30,%eax
    1a78:	83 f8 09             	cmp    $0x9,%eax
    1a7b:	76 53                	jbe    1ad0 <getint+0xb0>
    1a7d:	48 89 df             	mov    %rbx,%rdi
    1a80:	e8 1b f8 ff ff       	call   12a0 <getc@plt>
    1a85:	83 f8 23             	cmp    $0x23,%eax
    1a88:	75 e6                	jne    1a70 <getint+0x50>
    1a8a:	48 89 da             	mov    %rbx,%rdx
    1a8d:	be 28 23 00 00       	mov    $0x2328,%esi
    1a92:	4c 89 e7             	mov    %r12,%rdi
    1a95:	e8 66 f7 ff ff       	call   1200 <fgets@plt>
    1a9a:	eb e1                	jmp    1a7d <getint+0x5d>
    1a9c:	0f 1f 40 00          	nopl   0x0(%rax)
    1aa0:	48 8b 3d 79 75 00 00 	mov    0x7579(%rip),%rdi        # 9020 <stderr@GLIBC_2.2.5>
    1aa7:	48 8d 0d e4 59 00 00 	lea    0x59e4(%rip),%rcx        # 7492 <_IO_stdin_used+0x492>
    1aae:	48 8d 15 e0 59 00 00 	lea    0x59e0(%rip),%rdx        # 7495 <_IO_stdin_used+0x495>
    1ab5:	31 c0                	xor    %eax,%eax
    1ab7:	be 01 00 00 00       	mov    $0x1,%esi
    1abc:	e8 cf f7 ff ff       	call   1290 <__fprintf_chk@plt>
    1ac1:	31 ff                	xor    %edi,%edi
    1ac3:	e8 a8 f7 ff ff       	call   1270 <exit@plt>
    1ac8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    1acf:	00 
    1ad0:	45 31 e4             	xor    %r12d,%r12d
    1ad3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    1ad8:	43 8d 14 a4          	lea    (%r12,%r12,4),%edx
    1adc:	48 89 df             	mov    %rbx,%rdi
    1adf:	44 8d 24 50          	lea    (%rax,%rdx,2),%r12d
    1ae3:	e8 b8 f7 ff ff       	call   12a0 <getc@plt>
    1ae8:	83 e8 30             	sub    $0x30,%eax
    1aeb:	83 f8 09             	cmp    $0x9,%eax
    1aee:	76 e8                	jbe    1ad8 <getint+0xb8>
    1af0:	48 8b 84 24 18 27 00 	mov    0x2718(%rsp),%rax
    1af7:	00 
    1af8:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
    1aff:	00 00 
    1b01:	75 0e                	jne    1b11 <getint+0xf1>
    1b03:	48 81 c4 28 27 00 00 	add    $0x2728,%rsp
    1b0a:	44 89 e0             	mov    %r12d,%eax
    1b0d:	5b                   	pop    %rbx
    1b0e:	41 5c                	pop    %r12
    1b10:	c3                   	ret    
    1b11:	e8 ba f6 ff ff       	call   11d0 <__stack_chk_fail@plt>
    1b16:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    1b1d:	00 00 00 

0000000000001b20 <get_image>:
    1b20:	f3 0f 1e fa          	endbr64 
    1b24:	41 57                	push   %r15
    1b26:	41 56                	push   %r14
    1b28:	49 89 f6             	mov    %rsi,%r14
    1b2b:	48 8d 35 7d 59 00 00 	lea    0x597d(%rip),%rsi        # 74af <_IO_stdin_used+0x4af>
    1b32:	41 55                	push   %r13
    1b34:	49 89 d5             	mov    %rdx,%r13
    1b37:	41 54                	push   %r12
    1b39:	49 89 fc             	mov    %rdi,%r12
    1b3c:	55                   	push   %rbp
    1b3d:	53                   	push   %rbx
    1b3e:	48 89 cb             	mov    %rcx,%rbx
    1b41:	48 83 ec 08          	sub    $0x8,%rsp
    1b45:	e8 16 f7 ff ff       	call   1260 <fopen@plt>
    1b4a:	48 85 c0             	test   %rax,%rax
    1b4d:	0f 84 e3 00 00 00    	je     1c36 <get_image+0x116>
    1b53:	48 89 c5             	mov    %rax,%rbp
    1b56:	48 89 c7             	mov    %rax,%rdi
    1b59:	e8 92 f6 ff ff       	call   11f0 <fgetc@plt>
    1b5e:	48 89 ef             	mov    %rbp,%rdi
    1b61:	41 89 c7             	mov    %eax,%r15d
    1b64:	e8 87 f6 ff ff       	call   11f0 <fgetc@plt>
    1b69:	3c 35                	cmp    $0x35,%al
    1b6b:	75 06                	jne    1b73 <get_image+0x53>
    1b6d:	41 80 ff 50          	cmp    $0x50,%r15b
    1b71:	74 2d                	je     1ba0 <get_image+0x80>
    1b73:	4c 89 e1             	mov    %r12,%rcx
    1b76:	48 8d 15 c3 57 00 00 	lea    0x57c3(%rip),%rdx        # 7340 <_IO_stdin_used+0x340>
    1b7d:	48 8b 3d 9c 74 00 00 	mov    0x749c(%rip),%rdi        # 9020 <stderr@GLIBC_2.2.5>
    1b84:	be 01 00 00 00       	mov    $0x1,%esi
    1b89:	31 c0                	xor    %eax,%eax
    1b8b:	e8 00 f7 ff ff       	call   1290 <__fprintf_chk@plt>
    1b90:	31 ff                	xor    %edi,%edi
    1b92:	e8 d9 f6 ff ff       	call   1270 <exit@plt>
    1b97:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    1b9e:	00 00 
    1ba0:	48 89 ef             	mov    %rbp,%rdi
    1ba3:	31 c0                	xor    %eax,%eax
    1ba5:	e8 76 fe ff ff       	call   1a20 <getint>
    1baa:	48 89 ef             	mov    %rbp,%rdi
    1bad:	41 89 45 00          	mov    %eax,0x0(%r13)
    1bb1:	31 c0                	xor    %eax,%eax
    1bb3:	e8 68 fe ff ff       	call   1a20 <getint>
    1bb8:	48 89 ef             	mov    %rbp,%rdi
    1bbb:	89 03                	mov    %eax,(%rbx)
    1bbd:	31 c0                	xor    %eax,%eax
    1bbf:	e8 5c fe ff ff       	call   1a20 <getint>
    1bc4:	41 8b 7d 00          	mov    0x0(%r13),%edi
    1bc8:	0f af 3b             	imul   (%rbx),%edi
    1bcb:	48 63 ff             	movslq %edi,%rdi
    1bce:	e8 6d f6 ff ff       	call   1240 <malloc@plt>
    1bd3:	41 8b 55 00          	mov    0x0(%r13),%edx
    1bd7:	0f af 13             	imul   (%rbx),%edx
    1bda:	48 89 e9             	mov    %rbp,%rcx
    1bdd:	49 89 06             	mov    %rax,(%r14)
    1be0:	48 89 c7             	mov    %rax,%rdi
    1be3:	be 01 00 00 00       	mov    $0x1,%esi
    1be8:	48 63 d2             	movslq %edx,%rdx
    1beb:	e8 b0 f5 ff ff       	call   11a0 <fread@plt>
    1bf0:	48 85 c0             	test   %rax,%rax
    1bf3:	75 2b                	jne    1c20 <get_image+0x100>
    1bf5:	48 8b 3d 24 74 00 00 	mov    0x7424(%rip),%rdi        # 9020 <stderr@GLIBC_2.2.5>
    1bfc:	4c 89 e1             	mov    %r12,%rcx
    1bff:	be 01 00 00 00       	mov    $0x1,%esi
    1c04:	48 8d 15 bd 58 00 00 	lea    0x58bd(%rip),%rdx        # 74c8 <_IO_stdin_used+0x4c8>
    1c0b:	e8 80 f6 ff ff       	call   1290 <__fprintf_chk@plt>
    1c10:	31 ff                	xor    %edi,%edi
    1c12:	e8 59 f6 ff ff       	call   1270 <exit@plt>
    1c17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    1c1e:	00 00 
    1c20:	48 83 c4 08          	add    $0x8,%rsp
    1c24:	48 89 ef             	mov    %rbp,%rdi
    1c27:	5b                   	pop    %rbx
    1c28:	5d                   	pop    %rbp
    1c29:	41 5c                	pop    %r12
    1c2b:	41 5d                	pop    %r13
    1c2d:	41 5e                	pop    %r14
    1c2f:	41 5f                	pop    %r15
    1c31:	e9 8a f5 ff ff       	jmp    11c0 <fclose@plt>
    1c36:	4c 89 e1             	mov    %r12,%rcx
    1c39:	48 8d 15 71 58 00 00 	lea    0x5871(%rip),%rdx        # 74b1 <_IO_stdin_used+0x4b1>
    1c40:	e9 38 ff ff ff       	jmp    1b7d <get_image+0x5d>
    1c45:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    1c4c:	00 00 00 00 

0000000000001c50 <put_image>:
    1c50:	f3 0f 1e fa          	endbr64 
    1c54:	41 56                	push   %r14
    1c56:	41 89 ce             	mov    %ecx,%r14d
    1c59:	41 55                	push   %r13
    1c5b:	49 89 f5             	mov    %rsi,%r13
    1c5e:	48 8d 35 7c 58 00 00 	lea    0x587c(%rip),%rsi        # 74e1 <_IO_stdin_used+0x4e1>
    1c65:	41 54                	push   %r12
    1c67:	49 89 fc             	mov    %rdi,%r12
    1c6a:	55                   	push   %rbp
    1c6b:	53                   	push   %rbx
    1c6c:	89 d3                	mov    %edx,%ebx
    1c6e:	e8 ed f5 ff ff       	call   1260 <fopen@plt>
    1c73:	48 85 c0             	test   %rax,%rax
    1c76:	0f 84 a4 00 00 00    	je     1d20 <put_image+0xd0>
    1c7c:	48 89 c1             	mov    %rax,%rcx
    1c7f:	ba 03 00 00 00       	mov    $0x3,%edx
    1c84:	be 01 00 00 00       	mov    $0x1,%esi
    1c89:	48 89 c5             	mov    %rax,%rbp
    1c8c:	48 8d 3d 67 58 00 00 	lea    0x5867(%rip),%rdi        # 74fa <_IO_stdin_used+0x4fa>
    1c93:	e8 e8 f5 ff ff       	call   1280 <fwrite@plt>
    1c98:	89 d9                	mov    %ebx,%ecx
    1c9a:	41 0f af de          	imul   %r14d,%ebx
    1c9e:	45 89 f0             	mov    %r14d,%r8d
    1ca1:	48 8d 15 56 58 00 00 	lea    0x5856(%rip),%rdx        # 74fe <_IO_stdin_used+0x4fe>
    1ca8:	be 01 00 00 00       	mov    $0x1,%esi
    1cad:	48 89 ef             	mov    %rbp,%rdi
    1cb0:	31 c0                	xor    %eax,%eax
    1cb2:	e8 d9 f5 ff ff       	call   1290 <__fprintf_chk@plt>
    1cb7:	48 89 e9             	mov    %rbp,%rcx
    1cba:	ba 04 00 00 00       	mov    $0x4,%edx
    1cbf:	be 01 00 00 00       	mov    $0x1,%esi
    1cc4:	48 8d 3d 3a 58 00 00 	lea    0x583a(%rip),%rdi        # 7505 <_IO_stdin_used+0x505>
    1ccb:	e8 b0 f5 ff ff       	call   1280 <fwrite@plt>
    1cd0:	48 63 f3             	movslq %ebx,%rsi
    1cd3:	48 89 e9             	mov    %rbp,%rcx
    1cd6:	ba 01 00 00 00       	mov    $0x1,%edx
    1cdb:	4c 89 ef             	mov    %r13,%rdi
    1cde:	e8 9d f5 ff ff       	call   1280 <fwrite@plt>
    1ce3:	48 83 f8 01          	cmp    $0x1,%rax
    1ce7:	74 27                	je     1d10 <put_image+0xc0>
    1ce9:	4c 89 e1             	mov    %r12,%rcx
    1cec:	48 8d 15 17 58 00 00 	lea    0x5817(%rip),%rdx        # 750a <_IO_stdin_used+0x50a>
    1cf3:	48 8b 3d 26 73 00 00 	mov    0x7326(%rip),%rdi        # 9020 <stderr@GLIBC_2.2.5>
    1cfa:	be 01 00 00 00       	mov    $0x1,%esi
    1cff:	31 c0                	xor    %eax,%eax
    1d01:	e8 8a f5 ff ff       	call   1290 <__fprintf_chk@plt>
    1d06:	31 ff                	xor    %edi,%edi
    1d08:	e8 63 f5 ff ff       	call   1270 <exit@plt>
    1d0d:	0f 1f 00             	nopl   (%rax)
    1d10:	5b                   	pop    %rbx
    1d11:	48 89 ef             	mov    %rbp,%rdi
    1d14:	5d                   	pop    %rbp
    1d15:	41 5c                	pop    %r12
    1d17:	41 5d                	pop    %r13
    1d19:	41 5e                	pop    %r14
    1d1b:	e9 a0 f4 ff ff       	jmp    11c0 <fclose@plt>
    1d20:	4c 89 e1             	mov    %r12,%rcx
    1d23:	48 8d 15 b9 57 00 00 	lea    0x57b9(%rip),%rdx        # 74e3 <_IO_stdin_used+0x4e3>
    1d2a:	eb c7                	jmp    1cf3 <put_image+0xa3>
    1d2c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001d30 <int_to_uchar>:
    1d30:	f3 0f 1e fa          	endbr64 
    1d34:	41 89 d0             	mov    %edx,%r8d
    1d37:	8b 0f                	mov    (%rdi),%ecx
    1d39:	49 89 f9             	mov    %rdi,%r9
    1d3c:	49 89 f2             	mov    %rsi,%r10
    1d3f:	45 85 c0             	test   %r8d,%r8d
    1d42:	0f 8e 65 01 00 00    	jle    1ead <int_to_uchar+0x17d>
    1d48:	41 8d 40 ff          	lea    -0x1(%r8),%eax
    1d4c:	83 f8 02             	cmp    $0x2,%eax
    1d4f:	0f 86 5b 01 00 00    	jbe    1eb0 <int_to_uchar+0x180>
    1d55:	44 89 c2             	mov    %r8d,%edx
    1d58:	66 0f 6e e1          	movd   %ecx,%xmm4
    1d5c:	48 89 f8             	mov    %rdi,%rax
    1d5f:	c1 ea 02             	shr    $0x2,%edx
    1d62:	66 0f 70 c4 00       	pshufd $0x0,%xmm4,%xmm0
    1d67:	83 ea 01             	sub    $0x1,%edx
    1d6a:	66 0f 6f d8          	movdqa %xmm0,%xmm3
    1d6e:	48 c1 e2 04          	shl    $0x4,%rdx
    1d72:	48 8d 54 17 10       	lea    0x10(%rdi,%rdx,1),%rdx
    1d77:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    1d7e:	00 00 
    1d80:	f3 0f 6f 08          	movdqu (%rax),%xmm1
    1d84:	66 0f 6f d0          	movdqa %xmm0,%xmm2
    1d88:	48 83 c0 10          	add    $0x10,%rax
    1d8c:	66 0f 66 d1          	pcmpgtd %xmm1,%xmm2
    1d90:	66 0f db c2          	pand   %xmm2,%xmm0
    1d94:	66 0f df d1          	pandn  %xmm1,%xmm2
    1d98:	66 0f eb c2          	por    %xmm2,%xmm0
    1d9c:	66 0f 6f d3          	movdqa %xmm3,%xmm2
    1da0:	66 0f 66 d1          	pcmpgtd %xmm1,%xmm2
    1da4:	66 0f db ca          	pand   %xmm2,%xmm1
    1da8:	66 0f df d3          	pandn  %xmm3,%xmm2
    1dac:	66 0f 6f da          	movdqa %xmm2,%xmm3
    1db0:	66 0f eb d9          	por    %xmm1,%xmm3
    1db4:	48 39 d0             	cmp    %rdx,%rax
    1db7:	75 c7                	jne    1d80 <int_to_uchar+0x50>
    1db9:	66 0f 6f d3          	movdqa %xmm3,%xmm2
    1dbd:	44 89 c0             	mov    %r8d,%eax
    1dc0:	66 0f 73 da 08       	psrldq $0x8,%xmm2
    1dc5:	83 e0 fc             	and    $0xfffffffc,%eax
    1dc8:	66 0f 6f ca          	movdqa %xmm2,%xmm1
    1dcc:	66 0f 66 cb          	pcmpgtd %xmm3,%xmm1
    1dd0:	66 0f db d9          	pand   %xmm1,%xmm3
    1dd4:	66 0f df ca          	pandn  %xmm2,%xmm1
    1dd8:	66 0f eb cb          	por    %xmm3,%xmm1
    1ddc:	66 0f 6f d9          	movdqa %xmm1,%xmm3
    1de0:	66 0f 73 db 04       	psrldq $0x4,%xmm3
    1de5:	66 0f 6f d3          	movdqa %xmm3,%xmm2
    1de9:	66 0f 66 d1          	pcmpgtd %xmm1,%xmm2
    1ded:	66 0f db ca          	pand   %xmm2,%xmm1
    1df1:	66 0f df d3          	pandn  %xmm3,%xmm2
    1df5:	66 0f eb d1          	por    %xmm1,%xmm2
    1df9:	66 0f 7e d7          	movd   %xmm2,%edi
    1dfd:	66 0f 6f d0          	movdqa %xmm0,%xmm2
    1e01:	66 0f 73 da 08       	psrldq $0x8,%xmm2
    1e06:	66 0f 6f ca          	movdqa %xmm2,%xmm1
    1e0a:	66 0f 66 c8          	pcmpgtd %xmm0,%xmm1
    1e0e:	66 0f db d1          	pand   %xmm1,%xmm2
    1e12:	66 0f df c8          	pandn  %xmm0,%xmm1
    1e16:	66 0f eb ca          	por    %xmm2,%xmm1
    1e1a:	66 0f 6f d1          	movdqa %xmm1,%xmm2
    1e1e:	66 0f 73 da 04       	psrldq $0x4,%xmm2
    1e23:	66 0f 6f c2          	movdqa %xmm2,%xmm0
    1e27:	66 0f 66 c1          	pcmpgtd %xmm1,%xmm0
    1e2b:	66 0f db d0          	pand   %xmm0,%xmm2
    1e2f:	66 0f df c1          	pandn  %xmm1,%xmm0
    1e33:	66 0f eb c2          	por    %xmm2,%xmm0
    1e37:	66 0f 7e c1          	movd   %xmm0,%ecx
    1e3b:	41 f6 c0 03          	test   $0x3,%r8b
    1e3f:	74 47                	je     1e88 <int_to_uchar+0x158>
    1e41:	48 63 d0             	movslq %eax,%rdx
    1e44:	48 8d 34 95 00 00 00 	lea    0x0(,%rdx,4),%rsi
    1e4b:	00 
    1e4c:	41 8b 14 91          	mov    (%r9,%rdx,4),%edx
    1e50:	39 d1                	cmp    %edx,%ecx
    1e52:	0f 4c ca             	cmovl  %edx,%ecx
    1e55:	39 d7                	cmp    %edx,%edi
    1e57:	0f 4f fa             	cmovg  %edx,%edi
    1e5a:	8d 50 01             	lea    0x1(%rax),%edx
    1e5d:	41 39 d0             	cmp    %edx,%r8d
    1e60:	7e 26                	jle    1e88 <int_to_uchar+0x158>
    1e62:	41 8b 54 31 04       	mov    0x4(%r9,%rsi,1),%edx
    1e67:	39 d1                	cmp    %edx,%ecx
    1e69:	0f 4c ca             	cmovl  %edx,%ecx
    1e6c:	39 d7                	cmp    %edx,%edi
    1e6e:	0f 4f fa             	cmovg  %edx,%edi
    1e71:	83 c0 02             	add    $0x2,%eax
    1e74:	41 39 c0             	cmp    %eax,%r8d
    1e77:	7e 0f                	jle    1e88 <int_to_uchar+0x158>
    1e79:	41 8b 44 31 08       	mov    0x8(%r9,%rsi,1),%eax
    1e7e:	39 c1                	cmp    %eax,%ecx
    1e80:	0f 4c c8             	cmovl  %eax,%ecx
    1e83:	39 c7                	cmp    %eax,%edi
    1e85:	0f 4f f8             	cmovg  %eax,%edi
    1e88:	29 f9                	sub    %edi,%ecx
    1e8a:	31 f6                	xor    %esi,%esi
    1e8c:	0f 1f 40 00          	nopl   0x0(%rax)
    1e90:	41 8b 14 b1          	mov    (%r9,%rsi,4),%edx
    1e94:	29 fa                	sub    %edi,%edx
    1e96:	89 d0                	mov    %edx,%eax
    1e98:	c1 e0 08             	shl    $0x8,%eax
    1e9b:	29 d0                	sub    %edx,%eax
    1e9d:	99                   	cltd   
    1e9e:	f7 f9                	idiv   %ecx
    1ea0:	41 88 04 32          	mov    %al,(%r10,%rsi,1)
    1ea4:	48 83 c6 01          	add    $0x1,%rsi
    1ea8:	49 39 f0             	cmp    %rsi,%r8
    1eab:	75 e3                	jne    1e90 <int_to_uchar+0x160>
    1ead:	31 c0                	xor    %eax,%eax
    1eaf:	c3                   	ret    
    1eb0:	89 cf                	mov    %ecx,%edi
    1eb2:	31 c0                	xor    %eax,%eax
    1eb4:	eb 8b                	jmp    1e41 <int_to_uchar+0x111>
    1eb6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    1ebd:	00 00 00 

0000000000001ec0 <setup_brightness_lut>:
    1ec0:	f3 0f 1e fa          	endbr64 
    1ec4:	41 54                	push   %r12
    1ec6:	41 89 f4             	mov    %esi,%r12d
    1ec9:	55                   	push   %rbp
    1eca:	48 89 fd             	mov    %rdi,%rbp
    1ecd:	bf 04 02 00 00       	mov    $0x204,%edi
    1ed2:	53                   	push   %rbx
    1ed3:	89 d3                	mov    %edx,%ebx
    1ed5:	48 83 ec 20          	sub    $0x20,%rsp
    1ed9:	e8 62 f3 ff ff       	call   1240 <malloc@plt>
    1ede:	66 0f ef ed          	pxor   %xmm5,%xmm5
    1ee2:	f2 0f 10 3d 96 57 00 	movsd  0x5796(%rip),%xmm7        # 7680 <_IO_stdin_used+0x680>
    1ee9:	00 
    1eea:	f3 0f 10 35 7e 57 00 	movss  0x577e(%rip),%xmm6        # 7670 <_IO_stdin_used+0x670>
    1ef1:	00 
    1ef2:	f3 41 0f 2a ec       	cvtsi2ss %r12d,%xmm5
    1ef7:	48 05 02 01 00 00    	add    $0x102,%rax
    1efd:	83 fb 06             	cmp    $0x6,%ebx
    1f00:	0f 29 34 24          	movaps %xmm6,(%rsp)
    1f04:	48 89 45 00          	mov    %rax,0x0(%rbp)
    1f08:	48 c7 c3 00 ff ff ff 	mov    $0xffffffffffffff00,%rbx
    1f0f:	f2 0f 11 7c 24 18    	movsd  %xmm7,0x18(%rsp)
    1f15:	f3 0f 11 6c 24 14    	movss  %xmm5,0x14(%rsp)
    1f1b:	74 53                	je     1f70 <setup_brightness_lut+0xb0>
    1f1d:	0f 1f 00             	nopl   (%rax)
    1f20:	66 0f ef c0          	pxor   %xmm0,%xmm0
    1f24:	f3 0f 2a c3          	cvtsi2ss %ebx,%xmm0
    1f28:	f3 0f 5e 44 24 14    	divss  0x14(%rsp),%xmm0
    1f2e:	f3 0f 59 c0          	mulss  %xmm0,%xmm0
    1f32:	0f 57 04 24          	xorps  (%rsp),%xmm0
    1f36:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    1f3a:	e8 71 f3 ff ff       	call   12b0 <exp@plt>
    1f3f:	f2 0f 59 44 24 18    	mulsd  0x18(%rsp),%xmm0
    1f45:	48 8b 45 00          	mov    0x0(%rbp),%rax
    1f49:	f2 0f 5a c0          	cvtsd2ss %xmm0,%xmm0
    1f4d:	f3 0f 2c d0          	cvttss2si %xmm0,%edx
    1f51:	88 14 18             	mov    %dl,(%rax,%rbx,1)
    1f54:	48 83 c3 01          	add    $0x1,%rbx
    1f58:	48 81 fb 01 01 00 00 	cmp    $0x101,%rbx
    1f5f:	75 bf                	jne    1f20 <setup_brightness_lut+0x60>
    1f61:	48 83 c4 20          	add    $0x20,%rsp
    1f65:	5b                   	pop    %rbx
    1f66:	5d                   	pop    %rbp
    1f67:	41 5c                	pop    %r12
    1f69:	c3                   	ret    
    1f6a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1f70:	66 0f ef c9          	pxor   %xmm1,%xmm1
    1f74:	f3 0f 2a cb          	cvtsi2ss %ebx,%xmm1
    1f78:	f3 0f 5e 4c 24 14    	divss  0x14(%rsp),%xmm1
    1f7e:	f3 0f 59 c9          	mulss  %xmm1,%xmm1
    1f82:	0f 28 c1             	movaps %xmm1,%xmm0
    1f85:	f3 0f 59 c1          	mulss  %xmm1,%xmm0
    1f89:	f3 0f 59 c1          	mulss  %xmm1,%xmm0
    1f8d:	0f 57 04 24          	xorps  (%rsp),%xmm0
    1f91:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    1f95:	e8 16 f3 ff ff       	call   12b0 <exp@plt>
    1f9a:	f2 0f 59 44 24 18    	mulsd  0x18(%rsp),%xmm0
    1fa0:	48 8b 45 00          	mov    0x0(%rbp),%rax
    1fa4:	f2 0f 5a c0          	cvtsd2ss %xmm0,%xmm0
    1fa8:	f3 0f 2c d0          	cvttss2si %xmm0,%edx
    1fac:	88 14 18             	mov    %dl,(%rax,%rbx,1)
    1faf:	48 83 c3 01          	add    $0x1,%rbx
    1fb3:	48 81 fb 01 01 00 00 	cmp    $0x101,%rbx
    1fba:	75 b4                	jne    1f70 <setup_brightness_lut+0xb0>
    1fbc:	eb a3                	jmp    1f61 <setup_brightness_lut+0xa1>
    1fbe:	66 90                	xchg   %ax,%ax

0000000000001fc0 <susan_principle>:
    1fc0:	f3 0f 1e fa          	endbr64 
    1fc4:	41 57                	push   %r15
    1fc6:	41 56                	push   %r14
    1fc8:	45 89 ce             	mov    %r9d,%r14d
    1fcb:	41 55                	push   %r13
    1fcd:	49 89 fd             	mov    %rdi,%r13
    1fd0:	48 89 f7             	mov    %rsi,%rdi
    1fd3:	31 f6                	xor    %esi,%esi
    1fd5:	41 54                	push   %r12
    1fd7:	45 89 c4             	mov    %r8d,%r12d
    1fda:	55                   	push   %rbp
    1fdb:	89 cd                	mov    %ecx,%ebp
    1fdd:	53                   	push   %rbx
    1fde:	48 89 d3             	mov    %rdx,%rbx
    1fe1:	44 89 c2             	mov    %r8d,%edx
    1fe4:	41 0f af d1          	imul   %r9d,%edx
    1fe8:	48 83 ec 48          	sub    $0x48,%rsp
    1fec:	48 63 d2             	movslq %edx,%rdx
    1fef:	48 c1 e2 02          	shl    $0x2,%rdx
    1ff3:	e8 e8 f1 ff ff       	call   11e0 <memset@plt>
    1ff8:	48 89 c7             	mov    %rax,%rdi
    1ffb:	41 8d 46 fd          	lea    -0x3(%r14),%eax
    1fff:	89 44 24 14          	mov    %eax,0x14(%rsp)
    2003:	83 f8 03             	cmp    $0x3,%eax
    2006:	0f 8e 9c 03 00 00    	jle    23a8 <susan_principle+0x3e8>
    200c:	41 83 fc 06          	cmp    $0x6,%r12d
    2010:	0f 8e 92 03 00 00    	jle    23a8 <susan_principle+0x3e8>
    2016:	43 8d 14 64          	lea    (%r12,%r12,2),%edx
    201a:	4d 63 cc             	movslq %r12d,%r9
    201d:	c7 44 24 10 03 00 00 	movl   $0x3,0x10(%rsp)
    2024:	00 
    2025:	48 63 d2             	movslq %edx,%rdx
    2028:	4b 8d 34 09          	lea    (%r9,%r9,1),%rsi
    202c:	4a 8d 0c 8d 00 00 00 	lea    0x0(,%r9,4),%rcx
    2033:	00 
    2034:	48 8d 3c 97          	lea    (%rdi,%rdx,4),%rdi
    2038:	4a 8d 04 0e          	lea    (%rsi,%r9,1),%rax
    203c:	ba 02 00 00 00       	mov    $0x2,%edx
    2041:	48 89 74 24 20       	mov    %rsi,0x20(%rsp)
    2046:	48 89 3c 24          	mov    %rdi,(%rsp)
    204a:	49 8d 79 01          	lea    0x1(%r9),%rdi
    204e:	48 29 c2             	sub    %rax,%rdx
    2051:	49 01 c5             	add    %rax,%r13
    2054:	48 89 7c 24 30       	mov    %rdi,0x30(%rsp)
    2059:	48 8d 7e 02          	lea    0x2(%rsi),%rdi
    205d:	41 8d 44 24 f9       	lea    -0x7(%r12),%eax
    2062:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
    2067:	4c 8d 70 04          	lea    0x4(%rax),%r14
    206b:	48 89 7c 24 38       	mov    %rdi,0x38(%rsp)
    2070:	48 89 54 24 28       	mov    %rdx,0x28(%rsp)
    2075:	0f 1f 00             	nopl   (%rax)
    2078:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    207d:	4c 89 ee             	mov    %r13,%rsi
    2080:	4d 8d 45 01          	lea    0x1(%r13),%r8
    2084:	41 ba 03 00 00 00    	mov    $0x3,%r10d
    208a:	4c 29 ce             	sub    %r9,%rsi
    208d:	4a 8d 0c 28          	lea    (%rax,%r13,1),%rcx
    2091:	48 8b 44 24 30       	mov    0x30(%rsp),%rax
    2096:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
    209b:	4a 8d 3c 28          	lea    (%rax,%r13,1),%rdi
    209f:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    20a4:	4a 8d 14 28          	lea    (%rax,%r13,1),%rdx
    20a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    20af:	00 
    20b0:	43 0f b6 44 15 00    	movzbl 0x0(%r13,%r10,1),%eax
    20b6:	44 0f b6 21          	movzbl (%rcx),%r12d
    20ba:	44 0f b6 79 01       	movzbl 0x1(%rcx),%r15d
    20bf:	48 01 d8             	add    %rbx,%rax
    20c2:	49 89 c3             	mov    %rax,%r11
    20c5:	4d 29 e3             	sub    %r12,%r11
    20c8:	49 89 c4             	mov    %rax,%r12
    20cb:	4d 29 fc             	sub    %r15,%r12
    20ce:	45 0f b6 1b          	movzbl (%r11),%r11d
    20d2:	44 0f b6 79 02       	movzbl 0x2(%rcx),%r15d
    20d7:	45 0f b6 24 24       	movzbl (%r12),%r12d
    20dc:	47 8d 5c 23 64       	lea    0x64(%r11,%r12,1),%r11d
    20e1:	49 89 c4             	mov    %rax,%r12
    20e4:	4d 29 fc             	sub    %r15,%r12
    20e7:	46 0f b6 7c 09 ff    	movzbl -0x1(%rcx,%r9,1),%r15d
    20ed:	45 0f b6 24 24       	movzbl (%r12),%r12d
    20f2:	45 01 dc             	add    %r11d,%r12d
    20f5:	49 89 c3             	mov    %rax,%r11
    20f8:	4d 29 fb             	sub    %r15,%r11
    20fb:	46 0f b6 3c 09       	movzbl (%rcx,%r9,1),%r15d
    2100:	45 0f b6 1b          	movzbl (%r11),%r11d
    2104:	45 01 e3             	add    %r12d,%r11d
    2107:	49 89 c4             	mov    %rax,%r12
    210a:	4d 29 fc             	sub    %r15,%r12
    210d:	46 0f b6 7c 09 01    	movzbl 0x1(%rcx,%r9,1),%r15d
    2113:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2118:	45 01 dc             	add    %r11d,%r12d
    211b:	49 89 c3             	mov    %rax,%r11
    211e:	4d 29 fb             	sub    %r15,%r11
    2121:	46 0f b6 7c 09 02    	movzbl 0x2(%rcx,%r9,1),%r15d
    2127:	45 0f b6 1b          	movzbl (%r11),%r11d
    212b:	45 01 e3             	add    %r12d,%r11d
    212e:	49 89 c4             	mov    %rax,%r12
    2131:	4d 29 fc             	sub    %r15,%r12
    2134:	46 0f b6 7c 09 03    	movzbl 0x3(%rcx,%r9,1),%r15d
    213a:	45 0f b6 24 24       	movzbl (%r12),%r12d
    213f:	45 01 dc             	add    %r11d,%r12d
    2142:	49 89 c3             	mov    %rax,%r11
    2145:	4d 29 fb             	sub    %r15,%r11
    2148:	44 0f b6 3e          	movzbl (%rsi),%r15d
    214c:	45 0f b6 1b          	movzbl (%r11),%r11d
    2150:	45 01 e3             	add    %r12d,%r11d
    2153:	49 89 c4             	mov    %rax,%r12
    2156:	4d 29 fc             	sub    %r15,%r12
    2159:	44 0f b6 7e 01       	movzbl 0x1(%rsi),%r15d
    215e:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2163:	45 01 dc             	add    %r11d,%r12d
    2166:	49 89 c3             	mov    %rax,%r11
    2169:	4d 29 fb             	sub    %r15,%r11
    216c:	44 0f b6 7e 02       	movzbl 0x2(%rsi),%r15d
    2171:	45 0f b6 1b          	movzbl (%r11),%r11d
    2175:	45 01 e3             	add    %r12d,%r11d
    2178:	49 89 c4             	mov    %rax,%r12
    217b:	4d 29 fc             	sub    %r15,%r12
    217e:	44 0f b6 7e 03       	movzbl 0x3(%rsi),%r15d
    2183:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2188:	45 01 dc             	add    %r11d,%r12d
    218b:	49 89 c3             	mov    %rax,%r11
    218e:	4d 29 fb             	sub    %r15,%r11
    2191:	44 0f b6 7e 04       	movzbl 0x4(%rsi),%r15d
    2196:	45 0f b6 1b          	movzbl (%r11),%r11d
    219a:	45 01 e3             	add    %r12d,%r11d
    219d:	49 89 c4             	mov    %rax,%r12
    21a0:	4d 29 fc             	sub    %r15,%r12
    21a3:	44 0f b6 7e 05       	movzbl 0x5(%rsi),%r15d
    21a8:	45 0f b6 24 24       	movzbl (%r12),%r12d
    21ad:	45 01 dc             	add    %r11d,%r12d
    21b0:	49 89 c3             	mov    %rax,%r11
    21b3:	4d 29 fb             	sub    %r15,%r11
    21b6:	44 0f b6 7e 06       	movzbl 0x6(%rsi),%r15d
    21bb:	45 0f b6 1b          	movzbl (%r11),%r11d
    21bf:	45 01 e3             	add    %r12d,%r11d
    21c2:	49 89 c4             	mov    %rax,%r12
    21c5:	4d 29 fc             	sub    %r15,%r12
    21c8:	45 0f b6 78 ff       	movzbl -0x1(%r8),%r15d
    21cd:	45 0f b6 24 24       	movzbl (%r12),%r12d
    21d2:	45 01 dc             	add    %r11d,%r12d
    21d5:	49 89 c3             	mov    %rax,%r11
    21d8:	4d 29 fb             	sub    %r15,%r11
    21db:	45 0f b6 1b          	movzbl (%r11),%r11d
    21df:	45 0f b6 38          	movzbl (%r8),%r15d
    21e3:	45 01 e3             	add    %r12d,%r11d
    21e6:	49 89 c4             	mov    %rax,%r12
    21e9:	4d 29 fc             	sub    %r15,%r12
    21ec:	45 0f b6 78 01       	movzbl 0x1(%r8),%r15d
    21f1:	45 0f b6 24 24       	movzbl (%r12),%r12d
    21f6:	45 01 dc             	add    %r11d,%r12d
    21f9:	49 89 c3             	mov    %rax,%r11
    21fc:	4d 29 fb             	sub    %r15,%r11
    21ff:	45 0f b6 78 03       	movzbl 0x3(%r8),%r15d
    2204:	45 0f b6 1b          	movzbl (%r11),%r11d
    2208:	45 01 e3             	add    %r12d,%r11d
    220b:	49 89 c4             	mov    %rax,%r12
    220e:	4d 29 fc             	sub    %r15,%r12
    2211:	45 0f b6 78 04       	movzbl 0x4(%r8),%r15d
    2216:	45 0f b6 24 24       	movzbl (%r12),%r12d
    221b:	45 01 dc             	add    %r11d,%r12d
    221e:	49 89 c3             	mov    %rax,%r11
    2221:	4d 29 fb             	sub    %r15,%r11
    2224:	45 0f b6 78 05       	movzbl 0x5(%r8),%r15d
    2229:	45 0f b6 1b          	movzbl (%r11),%r11d
    222d:	45 01 e3             	add    %r12d,%r11d
    2230:	49 89 c4             	mov    %rax,%r12
    2233:	4d 29 fc             	sub    %r15,%r12
    2236:	44 0f b6 7f ff       	movzbl -0x1(%rdi),%r15d
    223b:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2240:	45 01 dc             	add    %r11d,%r12d
    2243:	49 89 c3             	mov    %rax,%r11
    2246:	4d 29 fb             	sub    %r15,%r11
    2249:	44 0f b6 3f          	movzbl (%rdi),%r15d
    224d:	45 0f b6 1b          	movzbl (%r11),%r11d
    2251:	45 01 e3             	add    %r12d,%r11d
    2254:	49 89 c4             	mov    %rax,%r12
    2257:	4d 29 fc             	sub    %r15,%r12
    225a:	44 0f b6 7f 01       	movzbl 0x1(%rdi),%r15d
    225f:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2264:	45 01 dc             	add    %r11d,%r12d
    2267:	49 89 c3             	mov    %rax,%r11
    226a:	4d 29 fb             	sub    %r15,%r11
    226d:	44 0f b6 7f 02       	movzbl 0x2(%rdi),%r15d
    2272:	45 0f b6 1b          	movzbl (%r11),%r11d
    2276:	45 01 e3             	add    %r12d,%r11d
    2279:	49 89 c4             	mov    %rax,%r12
    227c:	4d 29 fc             	sub    %r15,%r12
    227f:	44 0f b6 7f 03       	movzbl 0x3(%rdi),%r15d
    2284:	45 0f b6 24 24       	movzbl (%r12),%r12d
    2289:	45 01 dc             	add    %r11d,%r12d
    228c:	49 89 c3             	mov    %rax,%r11
    228f:	4d 29 fb             	sub    %r15,%r11
    2292:	44 0f b6 7f 04       	movzbl 0x4(%rdi),%r15d
    2297:	45 0f b6 1b          	movzbl (%r11),%r11d
    229b:	45 01 e3             	add    %r12d,%r11d
    229e:	49 89 c4             	mov    %rax,%r12
    22a1:	4d 29 fc             	sub    %r15,%r12
    22a4:	44 0f b6 7f 05       	movzbl 0x5(%rdi),%r15d
    22a9:	45 0f b6 24 24       	movzbl (%r12),%r12d
    22ae:	45 01 dc             	add    %r11d,%r12d
    22b1:	49 89 c3             	mov    %rax,%r11
    22b4:	4d 29 fb             	sub    %r15,%r11
    22b7:	44 0f b6 7a ff       	movzbl -0x1(%rdx),%r15d
    22bc:	45 0f b6 1b          	movzbl (%r11),%r11d
    22c0:	45 01 e3             	add    %r12d,%r11d
    22c3:	49 89 c4             	mov    %rax,%r12
    22c6:	4d 29 fc             	sub    %r15,%r12
    22c9:	44 0f b6 3a          	movzbl (%rdx),%r15d
    22cd:	45 0f b6 24 24       	movzbl (%r12),%r12d
    22d2:	45 01 dc             	add    %r11d,%r12d
    22d5:	49 89 c3             	mov    %rax,%r11
    22d8:	4d 29 fb             	sub    %r15,%r11
    22db:	44 0f b6 7a 01       	movzbl 0x1(%rdx),%r15d
    22e0:	45 0f b6 1b          	movzbl (%r11),%r11d
    22e4:	45 01 e3             	add    %r12d,%r11d
    22e7:	49 89 c4             	mov    %rax,%r12
    22ea:	4d 29 fc             	sub    %r15,%r12
    22ed:	44 0f b6 7a 02       	movzbl 0x2(%rdx),%r15d
    22f2:	45 0f b6 24 24       	movzbl (%r12),%r12d
    22f7:	45 01 dc             	add    %r11d,%r12d
    22fa:	49 89 c3             	mov    %rax,%r11
    22fd:	4d 29 fb             	sub    %r15,%r11
    2300:	45 0f b6 1b          	movzbl (%r11),%r11d
    2304:	44 0f b6 7a 03       	movzbl 0x3(%rdx),%r15d
    2309:	45 01 e3             	add    %r12d,%r11d
    230c:	49 89 c4             	mov    %rax,%r12
    230f:	4d 29 fc             	sub    %r15,%r12
    2312:	46 0f b6 3c 0a       	movzbl (%rdx,%r9,1),%r15d
    2317:	45 0f b6 24 24       	movzbl (%r12),%r12d
    231c:	45 01 dc             	add    %r11d,%r12d
    231f:	49 89 c3             	mov    %rax,%r11
    2322:	4d 29 fb             	sub    %r15,%r11
    2325:	46 0f b6 7c 0a 01    	movzbl 0x1(%rdx,%r9,1),%r15d
    232b:	45 0f b6 1b          	movzbl (%r11),%r11d
    232f:	45 01 e3             	add    %r12d,%r11d
    2332:	49 89 c4             	mov    %rax,%r12
    2335:	4d 29 fc             	sub    %r15,%r12
    2338:	45 0f b6 24 24       	movzbl (%r12),%r12d
    233d:	45 01 e3             	add    %r12d,%r11d
    2340:	46 0f b6 64 0a 02    	movzbl 0x2(%rdx,%r9,1),%r12d
    2346:	4c 29 e0             	sub    %r12,%rax
    2349:	0f b6 00             	movzbl (%rax),%eax
    234c:	44 01 d8             	add    %r11d,%eax
    234f:	39 e8                	cmp    %ebp,%eax
    2351:	7f 0e                	jg     2361 <susan_principle+0x3a1>
    2353:	41 89 eb             	mov    %ebp,%r11d
    2356:	41 29 c3             	sub    %eax,%r11d
    2359:	48 8b 04 24          	mov    (%rsp),%rax
    235d:	46 89 1c 90          	mov    %r11d,(%rax,%r10,4)
    2361:	49 83 c2 01          	add    $0x1,%r10
    2365:	48 83 c1 01          	add    $0x1,%rcx
    2369:	48 83 c6 01          	add    $0x1,%rsi
    236d:	49 83 c0 01          	add    $0x1,%r8
    2371:	48 83 c7 01          	add    $0x1,%rdi
    2375:	48 83 c2 01          	add    $0x1,%rdx
    2379:	4d 39 d6             	cmp    %r10,%r14
    237c:	0f 85 2e fd ff ff    	jne    20b0 <susan_principle+0xf0>
    2382:	83 44 24 10 01       	addl   $0x1,0x10(%rsp)
    2387:	4c 8b 6c 24 08       	mov    0x8(%rsp),%r13
    238c:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
    2391:	8b 44 24 10          	mov    0x10(%rsp),%eax
    2395:	48 01 34 24          	add    %rsi,(%rsp)
    2399:	4c 03 6c 24 20       	add    0x20(%rsp),%r13
    239e:	3b 44 24 14          	cmp    0x14(%rsp),%eax
    23a2:	0f 85 d0 fc ff ff    	jne    2078 <susan_principle+0xb8>
    23a8:	48 83 c4 48          	add    $0x48,%rsp
    23ac:	5b                   	pop    %rbx
    23ad:	5d                   	pop    %rbp
    23ae:	41 5c                	pop    %r12
    23b0:	41 5d                	pop    %r13
    23b2:	41 5e                	pop    %r14
    23b4:	41 5f                	pop    %r15
    23b6:	c3                   	ret    
    23b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    23be:	00 00 

00000000000023c0 <susan_principle_small>:
    23c0:	f3 0f 1e fa          	endbr64 
    23c4:	41 57                	push   %r15
    23c6:	48 89 f1             	mov    %rsi,%rcx
    23c9:	31 f6                	xor    %esi,%esi
    23cb:	41 56                	push   %r14
    23cd:	49 89 fe             	mov    %rdi,%r14
    23d0:	41 55                	push   %r13
    23d2:	41 54                	push   %r12
    23d4:	45 89 cc             	mov    %r9d,%r12d
    23d7:	55                   	push   %rbp
    23d8:	44 89 c5             	mov    %r8d,%ebp
    23db:	53                   	push   %rbx
    23dc:	48 89 d3             	mov    %rdx,%rbx
    23df:	44 89 c2             	mov    %r8d,%edx
    23e2:	41 0f af d1          	imul   %r9d,%edx
    23e6:	48 83 ec 28          	sub    $0x28,%rsp
    23ea:	48 63 d2             	movslq %edx,%rdx
    23ed:	48 89 7c 24 10       	mov    %rdi,0x10(%rsp)
    23f2:	48 89 cf             	mov    %rcx,%rdi
    23f5:	48 c1 e2 02          	shl    $0x2,%rdx
    23f9:	e8 e2 ed ff ff       	call   11e0 <memset@plt>
    23fe:	48 89 c1             	mov    %rax,%rcx
    2401:	41 8d 44 24 ff       	lea    -0x1(%r12),%eax
    2406:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    240a:	83 f8 01             	cmp    $0x1,%eax
    240d:	0f 8e 1a 01 00 00    	jle    252d <susan_principle_small+0x16d>
    2413:	83 fd 02             	cmp    $0x2,%ebp
    2416:	0f 8e 11 01 00 00    	jle    252d <susan_principle_small+0x16d>
    241c:	4c 63 d5             	movslq %ebp,%r10
    241f:	44 8d 45 fd          	lea    -0x3(%rbp),%r8d
    2423:	45 31 ed             	xor    %r13d,%r13d
    2426:	41 bc da 02 00 00    	mov    $0x2da,%r12d
    242c:	4a 8d 04 91          	lea    (%rcx,%r10,4),%rax
    2430:	4f 8d 1c 16          	lea    (%r14,%r10,1),%r11
    2434:	49 83 c0 02          	add    $0x2,%r8
    2438:	41 be 01 00 00 00    	mov    $0x1,%r14d
    243e:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
    2443:	4f 8d 4c 12 fe       	lea    -0x2(%r10,%r10,1),%r9
    2448:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    244f:	00 
    2450:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
    2455:	b9 01 00 00 00       	mov    $0x1,%ecx
    245a:	4a 8d 14 28          	lea    (%rax,%r13,1),%rdx
    245e:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
    2463:	4a 8d 2c a8          	lea    (%rax,%r13,4),%rbp
    2467:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    246e:	00 00 
    2470:	41 0f b6 04 0b       	movzbl (%r11,%rcx,1),%eax
    2475:	0f b6 3a             	movzbl (%rdx),%edi
    2478:	44 0f b6 7a 01       	movzbl 0x1(%rdx),%r15d
    247d:	48 01 d8             	add    %rbx,%rax
    2480:	48 89 c6             	mov    %rax,%rsi
    2483:	48 29 fe             	sub    %rdi,%rsi
    2486:	0f b6 3e             	movzbl (%rsi),%edi
    2489:	48 89 c6             	mov    %rax,%rsi
    248c:	4c 29 fe             	sub    %r15,%rsi
    248f:	44 0f b6 7a 02       	movzbl 0x2(%rdx),%r15d
    2494:	0f b6 36             	movzbl (%rsi),%esi
    2497:	8d 7c 37 64          	lea    0x64(%rdi,%rsi,1),%edi
    249b:	48 89 c6             	mov    %rax,%rsi
    249e:	4c 29 fe             	sub    %r15,%rsi
    24a1:	46 0f b6 3c 12       	movzbl (%rdx,%r10,1),%r15d
    24a6:	0f b6 36             	movzbl (%rsi),%esi
    24a9:	01 fe                	add    %edi,%esi
    24ab:	48 89 c7             	mov    %rax,%rdi
    24ae:	4c 29 ff             	sub    %r15,%rdi
    24b1:	46 0f b6 7c 12 02    	movzbl 0x2(%rdx,%r10,1),%r15d
    24b7:	0f b6 3f             	movzbl (%rdi),%edi
    24ba:	01 f7                	add    %esi,%edi
    24bc:	48 89 c6             	mov    %rax,%rsi
    24bf:	4c 29 fe             	sub    %r15,%rsi
    24c2:	46 0f b6 7c 0a 02    	movzbl 0x2(%rdx,%r9,1),%r15d
    24c8:	0f b6 36             	movzbl (%rsi),%esi
    24cb:	01 fe                	add    %edi,%esi
    24cd:	48 89 c7             	mov    %rax,%rdi
    24d0:	4c 29 ff             	sub    %r15,%rdi
    24d3:	46 0f b6 7c 0a 03    	movzbl 0x3(%rdx,%r9,1),%r15d
    24d9:	0f b6 3f             	movzbl (%rdi),%edi
    24dc:	01 f7                	add    %esi,%edi
    24de:	48 89 c6             	mov    %rax,%rsi
    24e1:	4c 29 fe             	sub    %r15,%rsi
    24e4:	0f b6 36             	movzbl (%rsi),%esi
    24e7:	01 fe                	add    %edi,%esi
    24e9:	42 0f b6 7c 0a 04    	movzbl 0x4(%rdx,%r9,1),%edi
    24ef:	48 29 f8             	sub    %rdi,%rax
    24f2:	0f b6 00             	movzbl (%rax),%eax
    24f5:	01 f0                	add    %esi,%eax
    24f7:	3d da 02 00 00       	cmp    $0x2da,%eax
    24fc:	7f 09                	jg     2507 <susan_principle_small+0x147>
    24fe:	44 89 e6             	mov    %r12d,%esi
    2501:	29 c6                	sub    %eax,%esi
    2503:	89 74 8d 00          	mov    %esi,0x0(%rbp,%rcx,4)
    2507:	48 83 c1 01          	add    $0x1,%rcx
    250b:	48 83 c2 01          	add    $0x1,%rdx
    250f:	49 39 c8             	cmp    %rcx,%r8
    2512:	0f 85 58 ff ff ff    	jne    2470 <susan_principle_small+0xb0>
    2518:	41 83 c6 01          	add    $0x1,%r14d
    251c:	4d 01 d5             	add    %r10,%r13
    251f:	4d 01 d3             	add    %r10,%r11
    2522:	44 3b 74 24 0c       	cmp    0xc(%rsp),%r14d
    2527:	0f 85 23 ff ff ff    	jne    2450 <susan_principle_small+0x90>
    252d:	48 83 c4 28          	add    $0x28,%rsp
    2531:	5b                   	pop    %rbx
    2532:	5d                   	pop    %rbp
    2533:	41 5c                	pop    %r12
    2535:	41 5d                	pop    %r13
    2537:	41 5e                	pop    %r14
    2539:	41 5f                	pop    %r15
    253b:	c3                   	ret    
    253c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000002540 <median>:
    2540:	f3 0f 1e fa          	endbr64 
    2544:	48 83 ec 38          	sub    $0x38,%rsp
    2548:	41 89 d0             	mov    %edx,%r8d
    254b:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    2552:	00 00 
    2554:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    2559:	31 c0                	xor    %eax,%eax
    255b:	8d 46 ff             	lea    -0x1(%rsi),%eax
    255e:	0f af c1             	imul   %ecx,%eax
    2561:	01 c2                	add    %eax,%edx
    2563:	01 c8                	add    %ecx,%eax
    2565:	48 63 d2             	movslq %edx,%rdx
    2568:	0f b6 74 17 ff       	movzbl -0x1(%rdi,%rdx,1),%esi
    256d:	66 0f 6e c6          	movd   %esi,%xmm0
    2571:	0f b6 34 17          	movzbl (%rdi,%rdx,1),%esi
    2575:	66 0f 6e f6          	movd   %esi,%xmm6
    2579:	42 8d 34 00          	lea    (%rax,%r8,1),%esi
    257d:	01 c8                	add    %ecx,%eax
    257f:	48 63 f6             	movslq %esi,%rsi
    2582:	44 01 c0             	add    %r8d,%eax
    2585:	66 0f 62 c6          	punpckldq %xmm6,%xmm0
    2589:	0f b6 4c 37 01       	movzbl 0x1(%rdi,%rsi,1),%ecx
    258e:	48 98                	cltq   
    2590:	66 0f 6f d8          	movdqa %xmm0,%xmm3
    2594:	44 0f b6 0c 07       	movzbl (%rdi,%rax,1),%r9d
    2599:	66 0f 6e c9          	movd   %ecx,%xmm1
    259d:	0f b6 4c 07 ff       	movzbl -0x1(%rdi,%rax,1),%ecx
    25a2:	0f b6 44 07 01       	movzbl 0x1(%rdi,%rax,1),%eax
    25a7:	66 41 0f 6e d1       	movd   %r9d,%xmm2
    25ac:	66 0f 6e e8          	movd   %eax,%xmm5
    25b0:	66 0f 6e f1          	movd   %ecx,%xmm6
    25b4:	0f b6 44 17 01       	movzbl 0x1(%rdi,%rdx,1),%eax
    25b9:	ba 07 00 00 00       	mov    $0x7,%edx
    25be:	66 0f 62 d5          	punpckldq %xmm5,%xmm2
    25c2:	66 0f 62 ce          	punpckldq %xmm6,%xmm1
    25c6:	66 0f 6c ca          	punpcklqdq %xmm2,%xmm1
    25ca:	66 0f 6e d0          	movd   %eax,%xmm2
    25ce:	0f b6 44 37 ff       	movzbl -0x1(%rdi,%rsi,1),%eax
    25d3:	0f 29 4c 24 10       	movaps %xmm1,0x10(%rsp)
    25d8:	66 0f 6e e0          	movd   %eax,%xmm4
    25dc:	66 0f 62 d4          	punpckldq %xmm4,%xmm2
    25e0:	66 0f 6c da          	punpcklqdq %xmm2,%xmm3
    25e4:	0f 29 1c 24          	movaps %xmm3,(%rsp)
    25e8:	e9 ce 00 00 00       	jmp    26bb <median+0x17b>
    25ed:	0f 1f 00             	nopl   (%rax)
    25f0:	8b 44 24 08          	mov    0x8(%rsp),%eax
    25f4:	66 0f 6e e9          	movd   %ecx,%xmm5
    25f8:	66 0f 6e c0          	movd   %eax,%xmm0
    25fc:	66 0f 62 c5          	punpckldq %xmm5,%xmm0
    2600:	39 c8                	cmp    %ecx,%eax
    2602:	7d 08                	jge    260c <median+0xcc>
    2604:	66 0f d6 44 24 04    	movq   %xmm0,0x4(%rsp)
    260a:	89 c8                	mov    %ecx,%eax
    260c:	83 fa 02             	cmp    $0x2,%edx
    260f:	0f 84 9e 00 00 00    	je     26b3 <median+0x173>
    2615:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
    2619:	66 0f 6e f0          	movd   %eax,%xmm6
    261d:	66 0f 6e c1          	movd   %ecx,%xmm0
    2621:	66 0f 62 c6          	punpckldq %xmm6,%xmm0
    2625:	39 c8                	cmp    %ecx,%eax
    2627:	7e 08                	jle    2631 <median+0xf1>
    2629:	66 0f d6 44 24 08    	movq   %xmm0,0x8(%rsp)
    262f:	89 c1                	mov    %eax,%ecx
    2631:	83 fa 03             	cmp    $0x3,%edx
    2634:	74 7d                	je     26b3 <median+0x173>
    2636:	8b 44 24 10          	mov    0x10(%rsp),%eax
    263a:	66 0f 6e f9          	movd   %ecx,%xmm7
    263e:	66 0f 6e c0          	movd   %eax,%xmm0
    2642:	66 0f 62 c7          	punpckldq %xmm7,%xmm0
    2646:	39 c1                	cmp    %eax,%ecx
    2648:	7e 08                	jle    2652 <median+0x112>
    264a:	66 0f d6 44 24 0c    	movq   %xmm0,0xc(%rsp)
    2650:	89 c8                	mov    %ecx,%eax
    2652:	83 fa 04             	cmp    $0x4,%edx
    2655:	74 5c                	je     26b3 <median+0x173>
    2657:	8b 4c 24 14          	mov    0x14(%rsp),%ecx
    265b:	66 0f 6e d8          	movd   %eax,%xmm3
    265f:	66 0f 6e c1          	movd   %ecx,%xmm0
    2663:	66 0f 62 c3          	punpckldq %xmm3,%xmm0
    2667:	39 c8                	cmp    %ecx,%eax
    2669:	7e 08                	jle    2673 <median+0x133>
    266b:	66 0f d6 44 24 10    	movq   %xmm0,0x10(%rsp)
    2671:	89 c1                	mov    %eax,%ecx
    2673:	83 fa 05             	cmp    $0x5,%edx
    2676:	74 3b                	je     26b3 <median+0x173>
    2678:	8b 44 24 18          	mov    0x18(%rsp),%eax
    267c:	66 0f 6e d1          	movd   %ecx,%xmm2
    2680:	66 0f 6e c0          	movd   %eax,%xmm0
    2684:	66 0f 62 c2          	punpckldq %xmm2,%xmm0
    2688:	39 c1                	cmp    %eax,%ecx
    268a:	7e 08                	jle    2694 <median+0x154>
    268c:	66 0f d6 44 24 14    	movq   %xmm0,0x14(%rsp)
    2692:	89 c8                	mov    %ecx,%eax
    2694:	83 fa 07             	cmp    $0x7,%edx
    2697:	75 1a                	jne    26b3 <median+0x173>
    2699:	66 0f 6e 44 24 1c    	movd   0x1c(%rsp),%xmm0
    269f:	66 0f 6e f8          	movd   %eax,%xmm7
    26a3:	66 0f 62 c7          	punpckldq %xmm7,%xmm0
    26a7:	3b 44 24 1c          	cmp    0x1c(%rsp),%eax
    26ab:	7e 06                	jle    26b3 <median+0x173>
    26ad:	66 0f d6 44 24 18    	movq   %xmm0,0x18(%rsp)
    26b3:	f3 0f 7e 04 24       	movq   (%rsp),%xmm0
    26b8:	83 ea 01             	sub    $0x1,%edx
    26bb:	66 0f 70 e0 e5       	pshufd $0xe5,%xmm0,%xmm4
    26c0:	66 0f 7e c0          	movd   %xmm0,%eax
    26c4:	66 0f 7e e1          	movd   %xmm4,%ecx
    26c8:	66 0f 70 c8 e1       	pshufd $0xe1,%xmm0,%xmm1
    26cd:	39 c1                	cmp    %eax,%ecx
    26cf:	7d 09                	jge    26da <median+0x19a>
    26d1:	66 0f d6 0c 24       	movq   %xmm1,(%rsp)
    26d6:	66 0f 7e c1          	movd   %xmm0,%ecx
    26da:	83 fa 01             	cmp    $0x1,%edx
    26dd:	0f 85 0d ff ff ff    	jne    25f0 <median+0xb0>
    26e3:	8b 54 24 10          	mov    0x10(%rsp),%edx
    26e7:	03 54 24 0c          	add    0xc(%rsp),%edx
    26eb:	89 d0                	mov    %edx,%eax
    26ed:	c1 e8 1f             	shr    $0x1f,%eax
    26f0:	01 d0                	add    %edx,%eax
    26f2:	d1 f8                	sar    %eax
    26f4:	48 8b 54 24 28       	mov    0x28(%rsp),%rdx
    26f9:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    2700:	00 00 
    2702:	75 05                	jne    2709 <median+0x1c9>
    2704:	48 83 c4 38          	add    $0x38,%rsp
    2708:	c3                   	ret    
    2709:	e8 c2 ea ff ff       	call   11d0 <__stack_chk_fail@plt>
    270e:	66 90                	xchg   %ax,%ax

0000000000002710 <enlarge>:
    2710:	f3 0f 1e fa          	endbr64 
    2714:	41 57                	push   %r15
    2716:	49 63 c0             	movslq %r8d,%rax
    2719:	45 31 ff             	xor    %r15d,%r15d
    271c:	41 56                	push   %r14
    271e:	49 89 ce             	mov    %rcx,%r14
    2721:	41 55                	push   %r13
    2723:	49 89 d5             	mov    %rdx,%r13
    2726:	41 54                	push   %r12
    2728:	49 89 c4             	mov    %rax,%r12
    272b:	55                   	push   %rbp
    272c:	8d 2c 00             	lea    (%rax,%rax,1),%ebp
    272f:	53                   	push   %rbx
    2730:	48 89 f3             	mov    %rsi,%rbx
    2733:	48 83 ec 28          	sub    $0x28,%rsp
    2737:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    273c:	8b 01                	mov    (%rcx),%eax
    273e:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
    2743:	85 c0                	test   %eax,%eax
    2745:	7e 42                	jle    2789 <enlarge+0x79>
    2747:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    274e:	00 00 
    2750:	49 63 55 00          	movslq 0x0(%r13),%rdx
    2754:	43 8d 04 3c          	lea    (%r12,%r15,1),%eax
    2758:	8d 3c 2a             	lea    (%rdx,%rbp,1),%edi
    275b:	48 89 d6             	mov    %rdx,%rsi
    275e:	0f af f8             	imul   %eax,%edi
    2761:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    2766:	41 0f af f7          	imul   %r15d,%esi
    276a:	41 83 c7 01          	add    $0x1,%r15d
    276e:	48 63 ff             	movslq %edi,%rdi
    2771:	48 03 7c 24 10       	add    0x10(%rsp),%rdi
    2776:	48 01 df             	add    %rbx,%rdi
    2779:	48 63 f6             	movslq %esi,%rsi
    277c:	48 03 30             	add    (%rax),%rsi
    277f:	e8 9c ea ff ff       	call   1220 <memcpy@plt>
    2784:	45 39 3e             	cmp    %r15d,(%r14)
    2787:	7f c7                	jg     2750 <enlarge+0x40>
    2789:	4d 63 fc             	movslq %r12d,%r15
    278c:	b9 01 00 00 00       	mov    $0x1,%ecx
    2791:	45 85 e4             	test   %r12d,%r12d
    2794:	0f 8e ff 00 00 00    	jle    2899 <enlarge+0x189>
    279a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    27a0:	49 63 55 00          	movslq 0x0(%r13),%rdx
    27a4:	44 89 e0             	mov    %r12d,%eax
    27a7:	44 8d 49 ff          	lea    -0x1(%rcx),%r9d
    27ab:	89 4c 24 1c          	mov    %ecx,0x1c(%rsp)
    27af:	29 c8                	sub    %ecx,%eax
    27b1:	44 89 4c 24 10       	mov    %r9d,0x10(%rsp)
    27b6:	8d 3c 2a             	lea    (%rdx,%rbp,1),%edi
    27b9:	48 89 d6             	mov    %rdx,%rsi
    27bc:	0f af f8             	imul   %eax,%edi
    27bf:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    27c4:	41 0f af f1          	imul   %r9d,%esi
    27c8:	48 63 ff             	movslq %edi,%rdi
    27cb:	4c 01 ff             	add    %r15,%rdi
    27ce:	48 63 f6             	movslq %esi,%rsi
    27d1:	48 03 30             	add    (%rax),%rsi
    27d4:	48 01 df             	add    %rbx,%rdi
    27d7:	e8 44 ea ff ff       	call   1220 <memcpy@plt>
    27dc:	41 8b 06             	mov    (%r14),%eax
    27df:	45 8b 55 00          	mov    0x0(%r13),%r10d
    27e3:	44 8b 4c 24 10       	mov    0x10(%rsp),%r9d
    27e8:	42 8d 3c 20          	lea    (%rax,%r12,1),%edi
    27ec:	41 8d 14 2a          	lea    (%r10,%rbp,1),%edx
    27f0:	44 01 cf             	add    %r9d,%edi
    27f3:	44 29 c8             	sub    %r9d,%eax
    27f6:	0f af fa             	imul   %edx,%edi
    27f9:	8d 70 ff             	lea    -0x1(%rax),%esi
    27fc:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    2801:	49 63 d2             	movslq %r10d,%rdx
    2804:	41 0f af f2          	imul   %r10d,%esi
    2808:	48 63 ff             	movslq %edi,%rdi
    280b:	4c 01 ff             	add    %r15,%rdi
    280e:	48 63 f6             	movslq %esi,%rsi
    2811:	48 03 30             	add    (%rax),%rsi
    2814:	48 01 df             	add    %rbx,%rdi
    2817:	e8 04 ea ff ff       	call   1220 <memcpy@plt>
    281c:	8b 4c 24 1c          	mov    0x1c(%rsp),%ecx
    2820:	89 c8                	mov    %ecx,%eax
    2822:	83 c1 01             	add    $0x1,%ecx
    2825:	44 39 e0             	cmp    %r12d,%eax
    2828:	0f 85 72 ff ff ff    	jne    27a0 <enlarge+0x90>
    282e:	41 8b 06             	mov    (%r14),%eax
    2831:	31 c9                	xor    %ecx,%ecx
    2833:	01 e8                	add    %ebp,%eax
    2835:	0f 1f 00             	nopl   (%rax)
    2838:	85 c0                	test   %eax,%eax
    283a:	7e 5d                	jle    2899 <enlarge+0x189>
    283c:	31 d2                	xor    %edx,%edx
    283e:	66 90                	xchg   %ax,%ax
    2840:	41 8b 45 00          	mov    0x0(%r13),%eax
    2844:	01 e8                	add    %ebp,%eax
    2846:	0f af c2             	imul   %edx,%eax
    2849:	44 01 e0             	add    %r12d,%eax
    284c:	8d 34 08             	lea    (%rax,%rcx,1),%esi
    284f:	83 e8 01             	sub    $0x1,%eax
    2852:	48 63 f6             	movslq %esi,%rsi
    2855:	29 c8                	sub    %ecx,%eax
    2857:	0f b6 34 33          	movzbl (%rbx,%rsi,1),%esi
    285b:	48 98                	cltq   
    285d:	40 88 34 03          	mov    %sil,(%rbx,%rax,1)
    2861:	41 8b 45 00          	mov    0x0(%r13),%eax
    2865:	01 e8                	add    %ebp,%eax
    2867:	0f af c2             	imul   %edx,%eax
    286a:	41 03 45 00          	add    0x0(%r13),%eax
    286e:	83 c2 01             	add    $0x1,%edx
    2871:	44 01 e0             	add    %r12d,%eax
    2874:	8d 70 ff             	lea    -0x1(%rax),%esi
    2877:	01 c8                	add    %ecx,%eax
    2879:	29 ce                	sub    %ecx,%esi
    287b:	48 98                	cltq   
    287d:	48 63 f6             	movslq %esi,%rsi
    2880:	0f b6 34 33          	movzbl (%rbx,%rsi,1),%esi
    2884:	40 88 34 03          	mov    %sil,(%rbx,%rax,1)
    2888:	41 8b 06             	mov    (%r14),%eax
    288b:	01 e8                	add    %ebp,%eax
    288d:	39 d0                	cmp    %edx,%eax
    288f:	7f af                	jg     2840 <enlarge+0x130>
    2891:	83 c1 01             	add    $0x1,%ecx
    2894:	41 39 cc             	cmp    %ecx,%r12d
    2897:	75 9f                	jne    2838 <enlarge+0x128>
    2899:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    289e:	41 01 6d 00          	add    %ebp,0x0(%r13)
    28a2:	41 01 2e             	add    %ebp,(%r14)
    28a5:	48 89 18             	mov    %rbx,(%rax)
    28a8:	48 83 c4 28          	add    $0x28,%rsp
    28ac:	31 c0                	xor    %eax,%eax
    28ae:	5b                   	pop    %rbx
    28af:	5d                   	pop    %rbp
    28b0:	41 5c                	pop    %r12
    28b2:	41 5d                	pop    %r13
    28b4:	41 5e                	pop    %r14
    28b6:	41 5f                	pop    %r15
    28b8:	c3                   	ret    
    28b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000028c0 <susan_smoothing>:
    28c0:	f3 0f 1e fa          	endbr64 
    28c4:	41 57                	push   %r15
    28c6:	f2 0f 5a c0          	cvtsd2ss %xmm0,%xmm0
    28ca:	41 56                	push   %r14
    28cc:	41 55                	push   %r13
    28ce:	41 54                	push   %r12
    28d0:	4d 89 c4             	mov    %r8,%r12
    28d3:	55                   	push   %rbp
    28d4:	53                   	push   %rbx
    28d5:	89 fb                	mov    %edi,%ebx
    28d7:	48 81 ec b8 00 00 00 	sub    $0xb8,%rsp
    28de:	48 89 b4 24 a8 00 00 	mov    %rsi,0xa8(%rsp)
    28e5:	00 
    28e6:	89 94 24 a4 00 00 00 	mov    %edx,0xa4(%rsp)
    28ed:	89 8c 24 a0 00 00 00 	mov    %ecx,0xa0(%rsp)
    28f4:	48 89 74 24 48       	mov    %rsi,0x48(%rsp)
    28f9:	c7 44 24 18 01 00 00 	movl   $0x1,0x18(%rsp)
    2900:	00 
    2901:	85 ff                	test   %edi,%edi
    2903:	75 1b                	jne    2920 <susan_smoothing+0x60>
    2905:	66 0f ef c9          	pxor   %xmm1,%xmm1
    2909:	f3 0f 5a c8          	cvtss2sd %xmm0,%xmm1
    290d:	f2 0f 59 0d 73 4d 00 	mulsd  0x4d73(%rip),%xmm1        # 7688 <_IO_stdin_used+0x688>
    2914:	00 
    2915:	f2 0f 2c c1          	cvttsd2si %xmm1,%eax
    2919:	83 c0 01             	add    $0x1,%eax
    291c:	89 44 24 18          	mov    %eax,0x18(%rsp)
    2920:	0f 2f 05 89 4d 00 00 	comiss 0x4d89(%rip),%xmm0        # 76b0 <_IO_stdin_used+0x6b0>
    2927:	77 3f                	ja     2968 <susan_smoothing+0xa8>
    2929:	8b 44 24 18          	mov    0x18(%rsp),%eax
    292d:	8b 8c 24 a4 00 00 00 	mov    0xa4(%rsp),%ecx
    2934:	44 8b 84 24 a0 00 00 	mov    0xa0(%rsp),%r8d
    293b:	00 
    293c:	44 8d 34 00          	lea    (%rax,%rax,1),%r14d
    2940:	41 39 ce             	cmp    %ecx,%r14d
    2943:	7d 05                	jge    294a <susan_smoothing+0x8a>
    2945:	45 39 c6             	cmp    %r8d,%r14d
    2948:	7c 57                	jl     29a1 <susan_smoothing+0xe1>
    294a:	8b 54 24 18          	mov    0x18(%rsp),%edx
    294e:	bf 01 00 00 00       	mov    $0x1,%edi
    2953:	48 8d 35 b6 4a 00 00 	lea    0x4ab6(%rip),%rsi        # 7410 <_IO_stdin_used+0x410>
    295a:	31 c0                	xor    %eax,%eax
    295c:	e8 ef e8 ff ff       	call   1250 <__printf_chk@plt>
    2961:	31 ff                	xor    %edi,%edi
    2963:	e8 08 e9 ff ff       	call   1270 <exit@plt>
    2968:	48 8d 35 01 4a 00 00 	lea    0x4a01(%rip),%rsi        # 7370 <_IO_stdin_used+0x370>
    296f:	bf 01 00 00 00       	mov    $0x1,%edi
    2974:	b8 01 00 00 00       	mov    $0x1,%eax
    2979:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    297d:	e8 ce e8 ff ff       	call   1250 <__printf_chk@plt>
    2982:	48 8d 3d 1f 4a 00 00 	lea    0x4a1f(%rip),%rdi        # 73a8 <_IO_stdin_used+0x3a8>
    2989:	e8 02 e8 ff ff       	call   1190 <puts@plt>
    298e:	48 8d 3d 53 4a 00 00 	lea    0x4a53(%rip),%rdi        # 73e8 <_IO_stdin_used+0x3e8>
    2995:	e8 f6 e7 ff ff       	call   1190 <puts@plt>
    299a:	31 ff                	xor    %edi,%edi
    299c:	e8 cf e8 ff ff       	call   1270 <exit@plt>
    29a1:	45 01 f0             	add    %r14d,%r8d
    29a4:	44 01 f1             	add    %r14d,%ecx
    29a7:	f3 0f 11 44 24 08    	movss  %xmm0,0x8(%rsp)
    29ad:	41 0f af c8          	imul   %r8d,%ecx
    29b1:	48 63 f9             	movslq %ecx,%rdi
    29b4:	e8 87 e8 ff ff       	call   1240 <malloc@plt>
    29b9:	44 8b 44 24 18       	mov    0x18(%rsp),%r8d
    29be:	48 8d 8c 24 a0 00 00 	lea    0xa0(%rsp),%rcx
    29c5:	00 
    29c6:	48 8d 94 24 a4 00 00 	lea    0xa4(%rsp),%rdx
    29cd:	00 
    29ce:	48 89 c6             	mov    %rax,%rsi
    29d1:	48 8d bc 24 a8 00 00 	lea    0xa8(%rsp),%rdi
    29d8:	00 
    29d9:	31 c0                	xor    %eax,%eax
    29db:	e8 30 fd ff ff       	call   2710 <enlarge>
    29e0:	85 db                	test   %ebx,%ebx
    29e2:	f3 0f 10 44 24 08    	movss  0x8(%rsp),%xmm0
    29e8:	0f 84 6c 02 00 00    	je     2c5a <susan_smoothing+0x39a>
    29ee:	8b 84 24 a0 00 00 00 	mov    0xa0(%rsp),%eax
    29f5:	83 e8 01             	sub    $0x1,%eax
    29f8:	89 84 24 88 00 00 00 	mov    %eax,0x88(%rsp)
    29ff:	83 f8 01             	cmp    $0x1,%eax
    2a02:	0f 8e 40 02 00 00    	jle    2c48 <susan_smoothing+0x388>
    2a08:	8b 84 24 a4 00 00 00 	mov    0xa4(%rsp),%eax
    2a0f:	48 8b 9c 24 a8 00 00 	mov    0xa8(%rsp),%rbx
    2a16:	00 
    2a17:	89 44 24 78          	mov    %eax,0x78(%rsp)
    2a1b:	48 89 5c 24 70       	mov    %rbx,0x70(%rsp)
    2a20:	83 f8 02             	cmp    $0x2,%eax
    2a23:	0f 8e 1f 02 00 00    	jle    2c48 <susan_smoothing+0x388>
    2a29:	4c 63 e8             	movslq %eax,%r13
    2a2c:	83 e8 03             	sub    $0x3,%eax
    2a2f:	4c 89 64 24 58       	mov    %r12,0x58(%rsp)
    2a34:	4c 01 eb             	add    %r13,%rbx
    2a37:	c7 44 24 6c 01 00 00 	movl   $0x1,0x6c(%rsp)
    2a3e:	00 
    2a3f:	48 89 5c 24 50       	mov    %rbx,0x50(%rsp)
    2a44:	48 8d 58 02          	lea    0x2(%rax),%rbx
    2a48:	48 83 c0 01          	add    $0x1,%rax
    2a4c:	48 89 84 24 90 00 00 	mov    %rax,0x90(%rsp)
    2a53:	00 
    2a54:	4b 8d 44 2d 00       	lea    0x0(%r13,%r13,1),%rax
    2a59:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
    2a60:	00 
    2a61:	48 89 5c 24 60       	mov    %rbx,0x60(%rsp)
    2a66:	4c 89 eb             	mov    %r13,%rbx
    2a69:	48 8b 44 24 50       	mov    0x50(%rsp),%rax
    2a6e:	bd 01 00 00 00       	mov    $0x1,%ebp
    2a73:	48 29 d8             	sub    %rbx,%rax
    2a76:	48 89 84 24 80 00 00 	mov    %rax,0x80(%rsp)
    2a7d:	00 
    2a7e:	49 89 c4             	mov    %rax,%r12
    2a81:	eb 37                	jmp    2aba <susan_smoothing+0x1fa>
    2a83:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    2a88:	8b 4c 24 78          	mov    0x78(%rsp),%ecx
    2a8c:	8b 74 24 6c          	mov    0x6c(%rsp),%esi
    2a90:	89 ea                	mov    %ebp,%edx
    2a92:	31 c0                	xor    %eax,%eax
    2a94:	48 8b 7c 24 70       	mov    0x70(%rsp),%rdi
    2a99:	e8 a2 fa ff ff       	call   2540 <median>
    2a9e:	48 8b 7c 24 48       	mov    0x48(%rsp),%rdi
    2aa3:	49 83 c4 01          	add    $0x1,%r12
    2aa7:	88 44 2f ff          	mov    %al,-0x1(%rdi,%rbp,1)
    2aab:	48 83 c5 01          	add    $0x1,%rbp
    2aaf:	48 39 6c 24 60       	cmp    %rbp,0x60(%rsp)
    2ab4:	0f 84 56 01 00 00    	je     2c10 <susan_smoothing+0x350>
    2aba:	48 8b 44 24 50       	mov    0x50(%rsp),%rax
    2abf:	41 0f b6 14 24       	movzbl (%r12),%edx
    2ac4:	89 6c 24 68          	mov    %ebp,0x68(%rsp)
    2ac8:	0f b6 34 28          	movzbl (%rax,%rbp,1),%esi
    2acc:	88 54 24 18          	mov    %dl,0x18(%rsp)
    2ad0:	40 88 74 24 08       	mov    %sil,0x8(%rsp)
    2ad5:	48 03 74 24 58       	add    0x58(%rsp),%rsi
    2ada:	48 89 f0             	mov    %rsi,%rax
    2add:	48 29 d0             	sub    %rdx,%rax
    2ae0:	41 0f b6 54 24 01    	movzbl 0x1(%r12),%edx
    2ae6:	0f b6 38             	movzbl (%rax),%edi
    2ae9:	48 89 f0             	mov    %rsi,%rax
    2aec:	48 29 d0             	sub    %rdx,%rax
    2aef:	88 54 24 10          	mov    %dl,0x10(%rsp)
    2af3:	41 0f b6 54 24 02    	movzbl 0x2(%r12),%edx
    2af9:	44 0f b6 38          	movzbl (%rax),%r15d
    2afd:	48 89 f0             	mov    %rsi,%rax
    2b00:	89 7c 24 38          	mov    %edi,0x38(%rsp)
    2b04:	48 29 d0             	sub    %rdx,%rax
    2b07:	88 54 24 1c          	mov    %dl,0x1c(%rsp)
    2b0b:	41 0f b6 14 1c       	movzbl (%r12,%rbx,1),%edx
    2b10:	44 0f b6 30          	movzbl (%rax),%r14d
    2b14:	48 89 f0             	mov    %rsi,%rax
    2b17:	42 8d 0c 3f          	lea    (%rdi,%r15,1),%ecx
    2b1b:	41 0f b6 7c 5c 01    	movzbl 0x1(%r12,%rbx,2),%edi
    2b21:	48 29 d0             	sub    %rdx,%rax
    2b24:	88 54 24 28          	mov    %dl,0x28(%rsp)
    2b28:	41 0f b6 54 1c 01    	movzbl 0x1(%r12,%rbx,1),%edx
    2b2e:	44 0f b6 28          	movzbl (%rax),%r13d
    2b32:	48 89 f0             	mov    %rsi,%rax
    2b35:	44 01 f1             	add    %r14d,%ecx
    2b38:	48 29 d0             	sub    %rdx,%rax
    2b3b:	88 54 24 20          	mov    %dl,0x20(%rsp)
    2b3f:	41 0f b6 54 1c 02    	movzbl 0x2(%r12,%rbx,1),%edx
    2b45:	0f b6 00             	movzbl (%rax),%eax
    2b48:	44 01 e9             	add    %r13d,%ecx
    2b4b:	88 54 24 2c          	mov    %dl,0x2c(%rsp)
    2b4f:	01 c1                	add    %eax,%ecx
    2b51:	89 44 24 40          	mov    %eax,0x40(%rsp)
    2b55:	48 89 f0             	mov    %rsi,%rax
    2b58:	48 29 d0             	sub    %rdx,%rax
    2b5b:	41 0f b6 14 5c       	movzbl (%r12,%rbx,2),%edx
    2b60:	44 0f b6 18          	movzbl (%rax),%r11d
    2b64:	48 89 f0             	mov    %rsi,%rax
    2b67:	48 29 d0             	sub    %rdx,%rax
    2b6a:	88 54 24 30          	mov    %dl,0x30(%rsp)
    2b6e:	48 89 fa             	mov    %rdi,%rdx
    2b71:	44 0f b6 10          	movzbl (%rax),%r10d
    2b75:	48 89 f0             	mov    %rsi,%rax
    2b78:	44 01 d9             	add    %r11d,%ecx
    2b7b:	48 29 f8             	sub    %rdi,%rax
    2b7e:	41 0f b6 7c 5c 02    	movzbl 0x2(%r12,%rbx,2),%edi
    2b84:	44 0f b6 08          	movzbl (%rax),%r9d
    2b88:	44 01 d1             	add    %r10d,%ecx
    2b8b:	48 29 fe             	sub    %rdi,%rsi
    2b8e:	48 89 f8             	mov    %rdi,%rax
    2b91:	44 0f b6 06          	movzbl (%rsi),%r8d
    2b95:	44 01 c9             	add    %r9d,%ecx
    2b98:	42 8d 7c 01 9c       	lea    -0x64(%rcx,%r8,1),%edi
    2b9d:	85 ff                	test   %edi,%edi
    2b9f:	0f 84 e3 fe ff ff    	je     2a88 <susan_smoothing+0x1c8>
    2ba5:	0f b6 4c 24 10       	movzbl 0x10(%rsp),%ecx
    2baa:	0f b6 74 24 18       	movzbl 0x18(%rsp),%esi
    2baf:	41 0f af d1          	imul   %r9d,%edx
    2bb3:	0f af 74 24 38       	imul   0x38(%rsp),%esi
    2bb8:	41 0f af cf          	imul   %r15d,%ecx
    2bbc:	41 0f af c0          	imul   %r8d,%eax
    2bc0:	01 ce                	add    %ecx,%esi
    2bc2:	0f b6 4c 24 1c       	movzbl 0x1c(%rsp),%ecx
    2bc7:	41 0f af ce          	imul   %r14d,%ecx
    2bcb:	01 f1                	add    %esi,%ecx
    2bcd:	0f b6 74 24 28       	movzbl 0x28(%rsp),%esi
    2bd2:	41 0f af f5          	imul   %r13d,%esi
    2bd6:	01 ce                	add    %ecx,%esi
    2bd8:	0f b6 4c 24 20       	movzbl 0x20(%rsp),%ecx
    2bdd:	0f af 4c 24 40       	imul   0x40(%rsp),%ecx
    2be2:	01 f1                	add    %esi,%ecx
    2be4:	0f b6 74 24 2c       	movzbl 0x2c(%rsp),%esi
    2be9:	41 0f af f3          	imul   %r11d,%esi
    2bed:	01 ce                	add    %ecx,%esi
    2bef:	0f b6 4c 24 30       	movzbl 0x30(%rsp),%ecx
    2bf4:	41 0f af ca          	imul   %r10d,%ecx
    2bf8:	01 f1                	add    %esi,%ecx
    2bfa:	01 ca                	add    %ecx,%edx
    2bfc:	01 d0                	add    %edx,%eax
    2bfe:	0f b6 54 24 08       	movzbl 0x8(%rsp),%edx
    2c03:	6b d2 9c             	imul   $0xffffff9c,%edx,%edx
    2c06:	01 d0                	add    %edx,%eax
    2c08:	99                   	cltd   
    2c09:	f7 ff                	idiv   %edi
    2c0b:	e9 8e fe ff ff       	jmp    2a9e <susan_smoothing+0x1de>
    2c10:	48 8b bc 24 90 00 00 	mov    0x90(%rsp),%rdi
    2c17:	00 
    2c18:	48 01 7c 24 48       	add    %rdi,0x48(%rsp)
    2c1d:	48 8b bc 24 80 00 00 	mov    0x80(%rsp),%rdi
    2c24:	00 
    2c25:	48 03 bc 24 98 00 00 	add    0x98(%rsp),%rdi
    2c2c:	00 
    2c2d:	83 44 24 6c 01       	addl   $0x1,0x6c(%rsp)
    2c32:	8b 44 24 6c          	mov    0x6c(%rsp),%eax
    2c36:	48 89 7c 24 50       	mov    %rdi,0x50(%rsp)
    2c3b:	3b 84 24 88 00 00 00 	cmp    0x88(%rsp),%eax
    2c42:	0f 85 21 fe ff ff    	jne    2a69 <susan_smoothing+0x1a9>
    2c48:	48 81 c4 b8 00 00 00 	add    $0xb8,%rsp
    2c4f:	5b                   	pop    %rbx
    2c50:	5d                   	pop    %rbp
    2c51:	41 5c                	pop    %r12
    2c53:	41 5d                	pop    %r13
    2c55:	41 5e                	pop    %r14
    2c57:	41 5f                	pop    %r15
    2c59:	c3                   	ret    
    2c5a:	8b 9c 24 a4 00 00 00 	mov    0xa4(%rsp),%ebx
    2c61:	41 8d 46 01          	lea    0x1(%r14),%eax
    2c65:	f3 0f 11 44 24 08    	movss  %xmm0,0x8(%rsp)
    2c6b:	89 5c 24 50          	mov    %ebx,0x50(%rsp)
    2c6f:	29 c3                	sub    %eax,%ebx
    2c71:	0f af c0             	imul   %eax,%eax
    2c74:	89 5c 24 10          	mov    %ebx,0x10(%rsp)
    2c78:	48 63 f8             	movslq %eax,%rdi
    2c7b:	e8 c0 e5 ff ff       	call   1240 <malloc@plt>
    2c80:	f3 0f 10 44 24 08    	movss  0x8(%rsp),%xmm0
    2c86:	8b 54 24 18          	mov    0x18(%rsp),%edx
    2c8a:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
    2c8f:	48 89 c1             	mov    %rax,%rcx
    2c92:	f3 0f 59 c0          	mulss  %xmm0,%xmm0
    2c96:	89 d6                	mov    %edx,%esi
    2c98:	f7 de                	neg    %esi
    2c9a:	89 74 24 2c          	mov    %esi,0x2c(%rsp)
    2c9e:	41 89 f5             	mov    %esi,%r13d
    2ca1:	f3 0f 11 44 24 08    	movss  %xmm0,0x8(%rsp)
    2ca7:	39 f2                	cmp    %esi,%edx
    2ca9:	0f 8c 97 00 00 00    	jl     2d46 <susan_smoothing+0x486>
    2caf:	44 89 f3             	mov    %r14d,%ebx
    2cb2:	48 89 5c 24 30       	mov    %rbx,0x30(%rsp)
    2cb7:	48 83 c3 01          	add    $0x1,%rbx
    2cbb:	48 01 d8             	add    %rbx,%rax
    2cbe:	48 89 5c 24 20       	mov    %rbx,0x20(%rsp)
    2cc3:	48 89 c3             	mov    %rax,%rbx
    2cc6:	89 f0                	mov    %esi,%eax
    2cc8:	29 ce                	sub    %ecx,%esi
    2cca:	29 d0                	sub    %edx,%eax
    2ccc:	89 f5                	mov    %esi,%ebp
    2cce:	83 e8 01             	sub    $0x1,%eax
    2cd1:	89 44 24 28          	mov    %eax,0x28(%rsp)
    2cd5:	8d 42 01             	lea    0x1(%rdx),%eax
    2cd8:	89 44 24 1c          	mov    %eax,0x1c(%rsp)
    2cdc:	45 89 ee             	mov    %r13d,%r14d
    2cdf:	49 89 df             	mov    %rbx,%r15
    2ce2:	4c 2b 7c 24 30       	sub    0x30(%rsp),%r15
    2ce7:	45 0f af f5          	imul   %r13d,%r14d
    2ceb:	49 83 ef 01          	sub    $0x1,%r15
    2cef:	90                   	nop
    2cf0:	42 8d 44 3d 00       	lea    0x0(%rbp,%r15,1),%eax
    2cf5:	66 0f ef c0          	pxor   %xmm0,%xmm0
    2cf9:	49 83 c7 01          	add    $0x1,%r15
    2cfd:	0f af c0             	imul   %eax,%eax
    2d00:	44 01 f0             	add    %r14d,%eax
    2d03:	f3 0f 2a c0          	cvtsi2ss %eax,%xmm0
    2d07:	0f 57 05 62 49 00 00 	xorps  0x4962(%rip),%xmm0        # 7670 <_IO_stdin_used+0x670>
    2d0e:	f3 0f 5e 44 24 08    	divss  0x8(%rsp),%xmm0
    2d14:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    2d18:	e8 93 e5 ff ff       	call   12b0 <exp@plt>
    2d1d:	f2 0f 59 05 5b 49 00 	mulsd  0x495b(%rip),%xmm0        # 7680 <_IO_stdin_used+0x680>
    2d24:	00 
    2d25:	f2 0f 2c c0          	cvttsd2si %xmm0,%eax
    2d29:	41 88 47 ff          	mov    %al,-0x1(%r15)
    2d2d:	49 39 df             	cmp    %rbx,%r15
    2d30:	75 be                	jne    2cf0 <susan_smoothing+0x430>
    2d32:	41 83 c5 01          	add    $0x1,%r13d
    2d36:	48 03 5c 24 20       	add    0x20(%rsp),%rbx
    2d3b:	03 6c 24 28          	add    0x28(%rsp),%ebp
    2d3f:	44 3b 6c 24 1c       	cmp    0x1c(%rsp),%r13d
    2d44:	75 96                	jne    2cdc <susan_smoothing+0x41c>
    2d46:	8b 84 24 a0 00 00 00 	mov    0xa0(%rsp),%eax
    2d4d:	8b 5c 24 18          	mov    0x18(%rsp),%ebx
    2d51:	29 d8                	sub    %ebx,%eax
    2d53:	89 44 24 6c          	mov    %eax,0x6c(%rsp)
    2d57:	39 d8                	cmp    %ebx,%eax
    2d59:	0f 8e e9 fe ff ff    	jle    2c48 <susan_smoothing+0x388>
    2d5f:	8b 74 24 50          	mov    0x50(%rsp),%esi
    2d63:	48 8b 8c 24 a8 00 00 	mov    0xa8(%rsp),%rcx
    2d6a:	00 
    2d6b:	89 f0                	mov    %esi,%eax
    2d6d:	48 89 4c 24 58       	mov    %rcx,0x58(%rsp)
    2d72:	29 d8                	sub    %ebx,%eax
    2d74:	89 44 24 20          	mov    %eax,0x20(%rsp)
    2d78:	89 c7                	mov    %eax,%edi
    2d7a:	39 d8                	cmp    %ebx,%eax
    2d7c:	0f 8e c6 fe ff ff    	jle    2c48 <susan_smoothing+0x388>
    2d82:	48 63 f6             	movslq %esi,%rsi
    2d85:	44 8d 3c 1b          	lea    (%rbx,%rbx,1),%r15d
    2d89:	89 5c 24 68          	mov    %ebx,0x68(%rsp)
    2d8d:	48 89 f0             	mov    %rsi,%rax
    2d90:	48 89 b4 24 80 00 00 	mov    %rsi,0x80(%rsp)
    2d97:	00 
    2d98:	48 63 f3             	movslq %ebx,%rsi
    2d9b:	0f af c3             	imul   %ebx,%eax
    2d9e:	48 89 f2             	mov    %rsi,%rdx
    2da1:	48 89 74 24 78       	mov    %rsi,0x78(%rsp)
    2da6:	48 f7 da             	neg    %rdx
    2da9:	48 89 54 24 60       	mov    %rdx,0x60(%rsp)
    2dae:	48 89 ca             	mov    %rcx,%rdx
    2db1:	48 01 f2             	add    %rsi,%rdx
    2db4:	48 98                	cltq   
    2db6:	48 01 d0             	add    %rdx,%rax
    2db9:	48 89 44 24 70       	mov    %rax,0x70(%rsp)
    2dbe:	48 63 44 24 10       	movslq 0x10(%rsp),%rax
    2dc3:	4e 8d 6c 38 01       	lea    0x1(%rax,%r15,1),%r13
    2dc8:	89 f8                	mov    %edi,%eax
    2dca:	29 d8                	sub    %ebx,%eax
    2dcc:	83 e8 01             	sub    $0x1,%eax
    2dcf:	48 83 c0 01          	add    $0x1,%rax
    2dd3:	48 89 84 24 88 00 00 	mov    %rax,0x88(%rsp)
    2dda:	00 
    2ddb:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    2de0:	48 8b 5c 24 60       	mov    0x60(%rsp),%rbx
    2de5:	48 83 c0 01          	add    $0x1,%rax
    2de9:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    2dee:	48 8b 44 24 70       	mov    0x70(%rsp),%rax
    2df3:	48 01 d8             	add    %rbx,%rax
    2df6:	48 89 44 24 30       	mov    %rax,0x30(%rsp)
    2dfb:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    2e00:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
    2e05:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    2e0a:	48 01 d8             	add    %rbx,%rax
    2e0d:	49 8d 5f 01          	lea    0x1(%r15),%rbx
    2e11:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    2e16:	8b 44 24 18          	mov    0x18(%rsp),%eax
    2e1a:	44 8d 70 01          	lea    0x1(%rax),%r14d
    2e1e:	66 90                	xchg   %ax,%ax
    2e20:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    2e25:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    2e2a:	4c 8b 4c 24 38       	mov    0x38(%rsp),%r9
    2e2f:	8b 6c 24 2c          	mov    0x2c(%rsp),%ebp
    2e33:	44 0f b6 1c 07       	movzbl (%rdi,%rax,1),%r11d
    2e38:	89 44 24 28          	mov    %eax,0x28(%rsp)
    2e3c:	31 ff                	xor    %edi,%edi
    2e3e:	49 01 c1             	add    %rax,%r9
    2e41:	44 88 5c 24 1c       	mov    %r11b,0x1c(%rsp)
    2e46:	39 6c 24 18          	cmp    %ebp,0x18(%rsp)
    2e4a:	0f 8c cd 00 00 00    	jl     2f1d <susan_smoothing+0x65d>
    2e50:	4c 8b 54 24 40       	mov    0x40(%rsp),%r10
    2e55:	31 f6                	xor    %esi,%esi
    2e57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    2e5e:	00 00 
    2e60:	31 d2                	xor    %edx,%edx
    2e62:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    2e68:	45 0f b6 04 11       	movzbl (%r9,%rdx,1),%r8d
    2e6d:	4c 89 d9             	mov    %r11,%rcx
    2e70:	4c 29 c1             	sub    %r8,%rcx
    2e73:	4c 89 c0             	mov    %r8,%rax
    2e76:	45 0f b6 04 12       	movzbl (%r10,%rdx,1),%r8d
    2e7b:	41 0f b6 0c 0c       	movzbl (%r12,%rcx,1),%ecx
    2e80:	41 0f af c8          	imul   %r8d,%ecx
    2e84:	0f af c1             	imul   %ecx,%eax
    2e87:	01 ce                	add    %ecx,%esi
    2e89:	01 c7                	add    %eax,%edi
    2e8b:	48 89 d0             	mov    %rdx,%rax
    2e8e:	48 83 c2 01          	add    $0x1,%rdx
    2e92:	49 39 c7             	cmp    %rax,%r15
    2e95:	75 d1                	jne    2e68 <susan_smoothing+0x5a8>
    2e97:	83 c5 01             	add    $0x1,%ebp
    2e9a:	49 01 da             	add    %rbx,%r10
    2e9d:	4d 01 e9             	add    %r13,%r9
    2ea0:	44 39 f5             	cmp    %r14d,%ebp
    2ea3:	75 bb                	jne    2e60 <susan_smoothing+0x5a0>
    2ea5:	81 ee 10 27 00 00    	sub    $0x2710,%esi
    2eab:	75 75                	jne    2f22 <susan_smoothing+0x662>
    2ead:	8b 4c 24 50          	mov    0x50(%rsp),%ecx
    2eb1:	8b 54 24 28          	mov    0x28(%rsp),%edx
    2eb5:	31 c0                	xor    %eax,%eax
    2eb7:	8b 74 24 68          	mov    0x68(%rsp),%esi
    2ebb:	48 8b 7c 24 58       	mov    0x58(%rsp),%rdi
    2ec0:	e8 7b f6 ff ff       	call   2540 <median>
    2ec5:	48 8b 7c 24 10       	mov    0x10(%rsp),%rdi
    2eca:	48 83 44 24 08 01    	addq   $0x1,0x8(%rsp)
    2ed0:	88 47 ff             	mov    %al,-0x1(%rdi)
    2ed3:	48 83 c7 01          	add    $0x1,%rdi
    2ed7:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    2edc:	48 89 7c 24 10       	mov    %rdi,0x10(%rsp)
    2ee1:	39 44 24 20          	cmp    %eax,0x20(%rsp)
    2ee5:	0f 8f 35 ff ff ff    	jg     2e20 <susan_smoothing+0x560>
    2eeb:	83 44 24 68 01       	addl   $0x1,0x68(%rsp)
    2ef0:	48 8b 9c 24 88 00 00 	mov    0x88(%rsp),%rbx
    2ef7:	00 
    2ef8:	48 8b bc 24 80 00 00 	mov    0x80(%rsp),%rdi
    2eff:	00 
    2f00:	48 01 5c 24 48       	add    %rbx,0x48(%rsp)
    2f05:	48 01 7c 24 60       	add    %rdi,0x60(%rsp)
    2f0a:	8b 44 24 68          	mov    0x68(%rsp),%eax
    2f0e:	39 44 24 6c          	cmp    %eax,0x6c(%rsp)
    2f12:	0f 85 c3 fe ff ff    	jne    2ddb <susan_smoothing+0x51b>
    2f18:	e9 2b fd ff ff       	jmp    2c48 <susan_smoothing+0x388>
    2f1d:	be f0 d8 ff ff       	mov    $0xffffd8f0,%esi
    2f22:	0f b6 44 24 1c       	movzbl 0x1c(%rsp),%eax
    2f27:	69 c0 f0 d8 ff ff    	imul   $0xffffd8f0,%eax,%eax
    2f2d:	01 f8                	add    %edi,%eax
    2f2f:	99                   	cltd   
    2f30:	f7 fe                	idiv   %esi
    2f32:	eb 91                	jmp    2ec5 <susan_smoothing+0x605>
    2f34:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    2f3b:	00 00 00 00 
    2f3f:	90                   	nop

0000000000002f40 <edge_draw>:
    2f40:	f3 0f 1e fa          	endbr64 
    2f44:	0f af ca             	imul   %edx,%ecx
    2f47:	45 85 c0             	test   %r8d,%r8d
    2f4a:	0f 85 90 00 00 00    	jne    2fe0 <edge_draw+0xa0>
    2f50:	4c 63 c9             	movslq %ecx,%r9
    2f53:	4c 63 c2             	movslq %edx,%r8
    2f56:	48 89 f0             	mov    %rsi,%rax
    2f59:	49 01 f1             	add    %rsi,%r9
    2f5c:	4d 8d 50 fe          	lea    -0x2(%r8),%r10
    2f60:	85 c9                	test   %ecx,%ecx
    2f62:	7e 77                	jle    2fdb <edge_draw+0x9b>
    2f64:	0f 1f 40 00          	nopl   0x0(%rax)
    2f68:	80 38 07             	cmpb   $0x7,(%rax)
    2f6b:	77 3b                	ja     2fa8 <edge_draw+0x68>
    2f6d:	48 89 c2             	mov    %rax,%rdx
    2f70:	41 bb ff ff ff ff    	mov    $0xffffffff,%r11d
    2f76:	48 29 f2             	sub    %rsi,%rdx
    2f79:	4c 29 c2             	sub    %r8,%rdx
    2f7c:	48 8d 54 17 ff       	lea    -0x1(%rdi,%rdx,1),%rdx
    2f81:	66 44 89 1a          	mov    %r11w,(%rdx)
    2f85:	41 bb ff ff ff ff    	mov    $0xffffffff,%r11d
    2f8b:	c6 42 02 ff          	movb   $0xff,0x2(%rdx)
    2f8f:	4a 8d 54 12 02       	lea    0x2(%rdx,%r10,1),%rdx
    2f94:	c6 02 ff             	movb   $0xff,(%rdx)
    2f97:	c6 42 02 ff          	movb   $0xff,0x2(%rdx)
    2f9b:	4a 8d 54 12 02       	lea    0x2(%rdx,%r10,1),%rdx
    2fa0:	66 44 89 1a          	mov    %r11w,(%rdx)
    2fa4:	c6 42 02 ff          	movb   $0xff,0x2(%rdx)
    2fa8:	48 83 c0 01          	add    $0x1,%rax
    2fac:	4c 39 c8             	cmp    %r9,%rax
    2faf:	75 b7                	jne    2f68 <edge_draw+0x28>
    2fb1:	48 89 f0             	mov    %rsi,%rax
    2fb4:	31 d2                	xor    %edx,%edx
    2fb6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    2fbd:	00 00 00 
    2fc0:	80 38 07             	cmpb   $0x7,(%rax)
    2fc3:	77 0b                	ja     2fd0 <edge_draw+0x90>
    2fc5:	49 89 c0             	mov    %rax,%r8
    2fc8:	49 29 f0             	sub    %rsi,%r8
    2fcb:	42 c6 04 07 00       	movb   $0x0,(%rdi,%r8,1)
    2fd0:	83 c2 01             	add    $0x1,%edx
    2fd3:	48 83 c0 01          	add    $0x1,%rax
    2fd7:	39 d1                	cmp    %edx,%ecx
    2fd9:	7f e5                	jg     2fc0 <edge_draw+0x80>
    2fdb:	31 c0                	xor    %eax,%eax
    2fdd:	c3                   	ret    
    2fde:	66 90                	xchg   %ax,%ax
    2fe0:	85 c9                	test   %ecx,%ecx
    2fe2:	7f cd                	jg     2fb1 <edge_draw+0x71>
    2fe4:	eb f5                	jmp    2fdb <edge_draw+0x9b>
    2fe6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    2fed:	00 00 00 

0000000000002ff0 <susan_thin>:
    2ff0:	f3 0f 1e fa          	endbr64 
    2ff4:	41 57                	push   %r15
    2ff6:	8d 41 fc             	lea    -0x4(%rcx),%eax
    2ff9:	41 56                	push   %r14
    2ffb:	41 55                	push   %r13
    2ffd:	41 54                	push   %r12
    2fff:	55                   	push   %rbp
    3000:	53                   	push   %rbx
    3001:	48 89 7c 24 a8       	mov    %rdi,-0x58(%rsp)
    3006:	89 44 24 f8          	mov    %eax,-0x8(%rsp)
    300a:	83 f8 04             	cmp    $0x4,%eax
    300d:	0f 8e 73 03 00 00    	jle    3386 <susan_thin+0x396>
    3013:	48 63 ca             	movslq %edx,%rcx
    3016:	49 89 f5             	mov    %rsi,%r13
    3019:	8d 72 fc             	lea    -0x4(%rdx),%esi
    301c:	c7 44 24 a0 04 00 00 	movl   $0x4,-0x60(%rsp)
    3023:	00 
    3024:	48 8d 04 09          	lea    (%rcx,%rcx,1),%rax
    3028:	89 74 24 b0          	mov    %esi,-0x50(%rsp)
    302c:	48 8d 78 01          	lea    0x1(%rax),%rdi
    3030:	48 83 c0 02          	add    $0x2,%rax
    3034:	48 89 7c 24 d0       	mov    %rdi,-0x30(%rsp)
    3039:	48 89 44 24 d8       	mov    %rax,-0x28(%rsp)
    303e:	83 fe 04             	cmp    $0x4,%esi
    3041:	0f 8e 3f 03 00 00    	jle    3386 <susan_thin+0x396>
    3047:	8d 04 12             	lea    (%rdx,%rdx,1),%eax
    304a:	89 54 24 a4          	mov    %edx,-0x5c(%rsp)
    304e:	4d 89 ec             	mov    %r13,%r12
    3051:	49 89 cf             	mov    %rcx,%r15
    3054:	89 44 24 e0          	mov    %eax,-0x20(%rsp)
    3058:	01 d0                	add    %edx,%eax
    305a:	f2 0f 10 0d 2e 46 00 	movsd  0x462e(%rip),%xmm1        # 7690 <_IO_stdin_used+0x690>
    3061:	00 
    3062:	89 44 24 fc          	mov    %eax,-0x4(%rsp)
    3066:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    306d:	00 00 00 
    3070:	44 8b 6c 24 a0       	mov    -0x60(%rsp),%r13d
    3075:	41 be 04 00 00 00    	mov    $0x4,%r14d
    307b:	41 8d 45 01          	lea    0x1(%r13),%eax
    307f:	89 44 24 9c          	mov    %eax,-0x64(%rsp)
    3083:	8b 44 24 a4          	mov    -0x5c(%rsp),%eax
    3087:	c1 e0 02             	shl    $0x2,%eax
    308a:	89 44 24 f4          	mov    %eax,-0xc(%rsp)
    308e:	eb 17                	jmp    30a7 <susan_thin+0xb7>
    3090:	c6 06 64             	movb   $0x64,(%rsi)
    3093:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    3098:	41 83 c6 01          	add    $0x1,%r14d
    309c:	44 39 74 24 b0       	cmp    %r14d,-0x50(%rsp)
    30a1:	0f 8e d1 02 00 00    	jle    3378 <susan_thin+0x388>
    30a7:	8b 4c 24 a4          	mov    -0x5c(%rsp),%ecx
    30ab:	8b 5c 24 9c          	mov    -0x64(%rsp),%ebx
    30af:	89 c8                	mov    %ecx,%eax
    30b1:	89 5c 24 a0          	mov    %ebx,-0x60(%rsp)
    30b5:	41 0f af c5          	imul   %r13d,%eax
    30b9:	46 8d 04 30          	lea    (%rax,%r14,1),%r8d
    30bd:	49 63 d0             	movslq %r8d,%rdx
    30c0:	49 8d 34 14          	lea    (%r12,%rdx,1),%rsi
    30c4:	0f b6 3e             	movzbl (%rsi),%edi
    30c7:	40 80 ff 07          	cmp    $0x7,%dil
    30cb:	77 cb                	ja     3098 <susan_thin+0xa8>
    30cd:	48 8d 1c 95 00 00 00 	lea    0x0(,%rdx,4),%rbx
    30d4:	00 
    30d5:	29 c8                	sub    %ecx,%eax
    30d7:	48 89 5c 24 c0       	mov    %rbx,-0x40(%rsp)
    30dc:	48 8b 5c 24 a8       	mov    -0x58(%rsp),%rbx
    30e1:	48 63 c8             	movslq %eax,%rcx
    30e4:	49 63 c6             	movslq %r14d,%rax
    30e7:	48 89 cd             	mov    %rcx,%rbp
    30ea:	48 01 c1             	add    %rax,%rcx
    30ed:	8b 1c 93             	mov    (%rbx,%rdx,4),%ebx
    30f0:	49 8d 44 0c ff       	lea    -0x1(%r12,%rcx,1),%rax
    30f5:	4e 8d 1c 38          	lea    (%rax,%r15,1),%r11
    30f9:	89 5c 24 c8          	mov    %ebx,-0x38(%rsp)
    30fd:	41 8d 5d ff          	lea    -0x1(%r13),%ebx
    3101:	89 5c 24 b8          	mov    %ebx,-0x48(%rsp)
    3105:	0f b6 18             	movzbl (%rax),%ebx
    3108:	80 fb 07             	cmp    $0x7,%bl
    310b:	88 5c 24 b7          	mov    %bl,-0x49(%rsp)
    310f:	0f 96 44 24 bc       	setbe  -0x44(%rsp)
    3114:	0f 96 c3             	setbe  %bl
    3117:	45 31 d2             	xor    %r10d,%r10d
    311a:	80 78 01 07          	cmpb   $0x7,0x1(%rax)
    311e:	41 0f 96 c2          	setbe  %r10b
    3122:	0f b6 db             	movzbl %bl,%ebx
    3125:	45 31 c9             	xor    %r9d,%r9d
    3128:	41 01 da             	add    %ebx,%r10d
    312b:	80 78 02 07          	cmpb   $0x7,0x2(%rax)
    312f:	41 0f 96 c1          	setbe  %r9b
    3133:	45 01 d1             	add    %r10d,%r9d
    3136:	45 31 d2             	xor    %r10d,%r10d
    3139:	41 80 3b 07          	cmpb   $0x7,(%r11)
    313d:	41 0f 96 c2          	setbe  %r10b
    3141:	45 01 ca             	add    %r9d,%r10d
    3144:	45 31 c9             	xor    %r9d,%r9d
    3147:	42 80 7c 38 02 07    	cmpb   $0x7,0x2(%rax,%r15,1)
    314d:	41 0f 96 c1          	setbe  %r9b
    3151:	45 01 d1             	add    %r10d,%r9d
    3154:	45 31 d2             	xor    %r10d,%r10d
    3157:	43 80 3c 3b 07       	cmpb   $0x7,(%r11,%r15,1)
    315c:	4c 8b 5c 24 d0       	mov    -0x30(%rsp),%r11
    3161:	41 0f 96 c2          	setbe  %r10b
    3165:	45 01 ca             	add    %r9d,%r10d
    3168:	45 31 c9             	xor    %r9d,%r9d
    316b:	42 80 3c 18 07       	cmpb   $0x7,(%rax,%r11,1)
    3170:	4c 8b 5c 24 d8       	mov    -0x28(%rsp),%r11
    3175:	41 0f 96 c1          	setbe  %r9b
    3179:	45 01 d1             	add    %r10d,%r9d
    317c:	45 31 d2             	xor    %r10d,%r10d
    317f:	42 80 3c 18 07       	cmpb   $0x7,(%rax,%r11,1)
    3184:	41 0f 96 c2          	setbe  %r10b
    3188:	45 01 d1             	add    %r10d,%r9d
    318b:	0f 84 ff fe ff ff    	je     3090 <susan_thin+0xa0>
    3191:	41 83 f9 01          	cmp    $0x1,%r9d
    3195:	0f 85 fd 01 00 00    	jne    3398 <susan_thin+0x3a8>
    319b:	40 80 ff 05          	cmp    $0x5,%dil
    319f:	0f 87 f3 fe ff ff    	ja     3098 <susan_thin+0xa8>
    31a5:	48 8b 5c 24 a8       	mov    -0x58(%rsp),%rbx
    31aa:	48 8d 34 8d 00 00 00 	lea    0x0(,%rcx,4),%rsi
    31b1:	00 
    31b2:	44 8b 04 8b          	mov    (%rbx,%rcx,4),%r8d
    31b6:	8b 44 33 fc          	mov    -0x4(%rbx,%rsi,1),%eax
    31ba:	44 89 44 24 bc       	mov    %r8d,-0x44(%rsp)
    31bf:	4c 8d 41 01          	lea    0x1(%rcx),%r8
    31c3:	4c 89 44 24 c8       	mov    %r8,-0x38(%rsp)
    31c8:	44 8b 44 33 04       	mov    0x4(%rbx,%rsi,1),%r8d
    31cd:	48 8b 74 24 c0       	mov    -0x40(%rsp),%rsi
    31d2:	44 8b 5c 33 fc       	mov    -0x4(%rbx,%rsi,1),%r11d
    31d7:	44 89 5c 24 b8       	mov    %r11d,-0x48(%rsp)
    31dc:	44 8b 5c 33 04       	mov    0x4(%rbx,%rsi,1),%r11d
    31e1:	8b 74 24 e0          	mov    -0x20(%rsp),%esi
    31e5:	01 ee                	add    %ebp,%esi
    31e7:	48 89 dd             	mov    %rbx,%rbp
    31ea:	44 01 f6             	add    %r14d,%esi
    31ed:	80 7c 24 b7 07       	cmpb   $0x7,-0x49(%rsp)
    31f2:	48 63 f6             	movslq %esi,%rsi
    31f5:	4c 8d 0c b5 00 00 00 	lea    0x0(,%rsi,4),%r9
    31fc:	00 
    31fd:	44 8b 54 b5 00       	mov    0x0(%rbp,%rsi,4),%r10d
    3202:	42 8b 5c 0b fc       	mov    -0x4(%rbx,%r9,1),%ebx
    3207:	46 8b 4c 0d 04       	mov    0x4(%rbp,%r9,1),%r9d
    320c:	0f 87 5e 04 00 00    	ja     3670 <susan_thin+0x680>
    3212:	45 01 c0             	add    %r8d,%r8d
    3215:	01 db                	add    %ebx,%ebx
    3217:	47 8d 1c 5b          	lea    (%r11,%r11,2),%r11d
    321b:	41 c1 e1 02          	shl    $0x2,%r9d
    321f:	c7 44 24 b8 00 00 00 	movl   $0x0,-0x48(%rsp)
    3226:	00 
    3227:	47 8d 14 52          	lea    (%r10,%r10,2),%r10d
    322b:	c7 44 24 bc 00 00 00 	movl   $0x0,-0x44(%rsp)
    3232:	00 
    3233:	31 c0                	xor    %eax,%eax
    3235:	8b 74 24 bc          	mov    -0x44(%rsp),%esi
    3239:	39 c6                	cmp    %eax,%esi
    323b:	7e 12                	jle    324f <susan_thin+0x25f>
    323d:	c7 44 24 e8 01 00 00 	movl   $0x1,-0x18(%rsp)
    3244:	00 
    3245:	89 f0                	mov    %esi,%eax
    3247:	c7 44 24 e4 00 00 00 	movl   $0x0,-0x1c(%rsp)
    324e:	00 
    324f:	41 39 c0             	cmp    %eax,%r8d
    3252:	7e 13                	jle    3267 <susan_thin+0x277>
    3254:	c7 44 24 e8 02 00 00 	movl   $0x2,-0x18(%rsp)
    325b:	00 
    325c:	44 89 c0             	mov    %r8d,%eax
    325f:	c7 44 24 e4 00 00 00 	movl   $0x0,-0x1c(%rsp)
    3266:	00 
    3267:	8b 74 24 b8          	mov    -0x48(%rsp),%esi
    326b:	39 c6                	cmp    %eax,%esi
    326d:	7e 12                	jle    3281 <susan_thin+0x291>
    326f:	c7 44 24 e4 01 00 00 	movl   $0x1,-0x1c(%rsp)
    3276:	00 
    3277:	89 f0                	mov    %esi,%eax
    3279:	c7 44 24 e8 00 00 00 	movl   $0x0,-0x18(%rsp)
    3280:	00 
    3281:	85 c0                	test   %eax,%eax
    3283:	79 12                	jns    3297 <susan_thin+0x2a7>
    3285:	c7 44 24 e8 01 00 00 	movl   $0x1,-0x18(%rsp)
    328c:	00 
    328d:	31 c0                	xor    %eax,%eax
    328f:	c7 44 24 e4 01 00 00 	movl   $0x1,-0x1c(%rsp)
    3296:	00 
    3297:	41 39 c3             	cmp    %eax,%r11d
    329a:	7e 13                	jle    32af <susan_thin+0x2bf>
    329c:	c7 44 24 e4 01 00 00 	movl   $0x1,-0x1c(%rsp)
    32a3:	00 
    32a4:	44 89 d8             	mov    %r11d,%eax
    32a7:	c7 44 24 e8 02 00 00 	movl   $0x2,-0x18(%rsp)
    32ae:	00 
    32af:	39 c3                	cmp    %eax,%ebx
    32b1:	7e 12                	jle    32c5 <susan_thin+0x2d5>
    32b3:	c7 44 24 e8 00 00 00 	movl   $0x0,-0x18(%rsp)
    32ba:	00 
    32bb:	89 d8                	mov    %ebx,%eax
    32bd:	c7 44 24 e4 02 00 00 	movl   $0x2,-0x1c(%rsp)
    32c4:	00 
    32c5:	41 39 c2             	cmp    %eax,%r10d
    32c8:	7e 13                	jle    32dd <susan_thin+0x2ed>
    32ca:	c7 44 24 e8 01 00 00 	movl   $0x1,-0x18(%rsp)
    32d1:	00 
    32d2:	44 89 d0             	mov    %r10d,%eax
    32d5:	c7 44 24 e4 02 00 00 	movl   $0x2,-0x1c(%rsp)
    32dc:	00 
    32dd:	41 39 c1             	cmp    %eax,%r9d
    32e0:	7e 13                	jle    32f5 <susan_thin+0x305>
    32e2:	c7 44 24 e8 02 00 00 	movl   $0x2,-0x18(%rsp)
    32e9:	00 
    32ea:	44 89 c8             	mov    %r9d,%eax
    32ed:	c7 44 24 e4 02 00 00 	movl   $0x2,-0x1c(%rsp)
    32f4:	00 
    32f5:	85 c0                	test   %eax,%eax
    32f7:	0f 8e 9b fd ff ff    	jle    3098 <susan_thin+0xa8>
    32fd:	8b 74 24 e4          	mov    -0x1c(%rsp),%esi
    3301:	8b 4c 24 e8          	mov    -0x18(%rsp),%ecx
    3305:	8d 57 01             	lea    0x1(%rdi),%edx
    3308:	42 8d 44 2e ff       	lea    -0x1(%rsi,%r13,1),%eax
    330d:	0f af 44 24 a4       	imul   -0x5c(%rsp),%eax
    3312:	44 01 f0             	add    %r14d,%eax
    3315:	01 c8                	add    %ecx,%eax
    3317:	40 80 ff 03          	cmp    $0x3,%dil
    331b:	bf 04 00 00 00       	mov    $0x4,%edi
    3320:	0f 46 d7             	cmovbe %edi,%edx
    3323:	48 98                	cltq   
    3325:	41 88 54 04 ff       	mov    %dl,-0x1(%r12,%rax,1)
    332a:	8d 04 71             	lea    (%rcx,%rsi,2),%eax
    332d:	83 f8 02             	cmp    $0x2,%eax
    3330:	0f 8f 62 fd ff ff    	jg     3098 <susan_thin+0xa8>
    3336:	46 8d 6c 2e ff       	lea    -0x1(%rsi,%r13,1),%r13d
    333b:	b8 04 00 00 00       	mov    $0x4,%eax
    3340:	46 8d 74 31 fe       	lea    -0x2(%rcx,%r14,1),%r14d
    3345:	41 39 c5             	cmp    %eax,%r13d
    3348:	44 0f 4c e8          	cmovl  %eax,%r13d
    334c:	0f 1f 40 00          	nopl   0x0(%rax)
    3350:	41 39 c6             	cmp    %eax,%r14d
    3353:	44 0f 4c f0          	cmovl  %eax,%r14d
    3357:	41 8d 45 01          	lea    0x1(%r13),%eax
    335b:	89 44 24 9c          	mov    %eax,-0x64(%rsp)
    335f:	89 44 24 a0          	mov    %eax,-0x60(%rsp)
    3363:	41 83 c6 01          	add    $0x1,%r14d
    3367:	44 39 74 24 b0       	cmp    %r14d,-0x50(%rsp)
    336c:	0f 8f 35 fd ff ff    	jg     30a7 <susan_thin+0xb7>
    3372:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    3378:	8b 74 24 9c          	mov    -0x64(%rsp),%esi
    337c:	39 74 24 f8          	cmp    %esi,-0x8(%rsp)
    3380:	0f 8f ea fc ff ff    	jg     3070 <susan_thin+0x80>
    3386:	5b                   	pop    %rbx
    3387:	31 c0                	xor    %eax,%eax
    3389:	5d                   	pop    %rbp
    338a:	41 5c                	pop    %r12
    338c:	41 5d                	pop    %r13
    338e:	41 5e                	pop    %r14
    3390:	41 5f                	pop    %r15
    3392:	c3                   	ret    
    3393:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    3398:	41 83 f9 02          	cmp    $0x2,%r9d
    339c:	0f 85 5c 01 00 00    	jne    34fe <susan_thin+0x50e>
    33a2:	45 0f b6 5c 0c 01    	movzbl 0x1(%r12,%rcx,1),%r11d
    33a8:	8b 44 24 e0          	mov    -0x20(%rsp),%eax
    33ac:	41 80 fb 07          	cmp    $0x7,%r11b
    33b0:	0f 96 44 24 c0       	setbe  -0x40(%rsp)
    33b5:	01 e8                	add    %ebp,%eax
    33b7:	0f b6 7c 24 c0       	movzbl -0x40(%rsp),%edi
    33bc:	89 44 24 ec          	mov    %eax,-0x14(%rsp)
    33c0:	44 01 f0             	add    %r14d,%eax
    33c3:	89 44 24 f0          	mov    %eax,-0x10(%rsp)
    33c7:	48 98                	cltq   
    33c9:	41 80 7c 04 ff 07    	cmpb   $0x7,-0x1(%r12,%rax,1)
    33cf:	41 0f 96 c2          	setbe  %r10b
    33d3:	41 80 7c 04 01 07    	cmpb   $0x7,0x1(%r12,%rax,1)
    33d9:	41 0f 96 c1          	setbe  %r9b
    33dd:	01 fb                	add    %edi,%ebx
    33df:	41 0f b6 fa          	movzbl %r10b,%edi
    33e3:	01 df                	add    %ebx,%edi
    33e5:	41 0f b6 d9          	movzbl %r9b,%ebx
    33e9:	01 df                	add    %ebx,%edi
    33eb:	83 ff 02             	cmp    $0x2,%edi
    33ee:	0f 84 dc 01 00 00    	je     35d0 <susan_thin+0x5e0>
    33f4:	41 80 3c 0c 07       	cmpb   $0x7,(%r12,%rcx,1)
    33f9:	41 0f 96 c0          	setbe  %r8b
    33fd:	41 80 7c 14 01 07    	cmpb   $0x7,0x1(%r12,%rdx,1)
    3403:	40 0f 96 c7          	setbe  %dil
    3407:	41 80 3c 04 07       	cmpb   $0x7,(%r12,%rax,1)
    340c:	41 0f 96 c1          	setbe  %r9b
    3410:	44 0f b6 df          	movzbl %dil,%r11d
    3414:	41 80 7c 14 ff 07    	cmpb   $0x7,-0x1(%r12,%rdx,1)
    341a:	41 0f b6 d0          	movzbl %r8b,%edx
    341e:	41 0f 96 c2          	setbe  %r10b
    3422:	41 01 d3             	add    %edx,%r11d
    3425:	41 0f b6 d1          	movzbl %r9b,%edx
    3429:	44 01 da             	add    %r11d,%edx
    342c:	45 0f b6 da          	movzbl %r10b,%r11d
    3430:	44 01 da             	add    %r11d,%edx
    3433:	83 fa 02             	cmp    $0x2,%edx
    3436:	0f 85 5c fc ff ff    	jne    3098 <susan_thin+0xa8>
    343c:	89 fa                	mov    %edi,%edx
    343e:	44 08 d2             	or     %r10b,%dl
    3441:	0f 84 51 fc ff ff    	je     3098 <susan_thin+0xa8>
    3447:	44 89 c2             	mov    %r8d,%edx
    344a:	44 08 ca             	or     %r9b,%dl
    344d:	0f 84 45 fc ff ff    	je     3098 <susan_thin+0xa8>
    3453:	8b 54 24 ec          	mov    -0x14(%rsp),%edx
    3457:	2b 54 24 fc          	sub    -0x4(%rsp),%edx
    345b:	42 8d 1c 32          	lea    (%rdx,%r14,1),%ebx
    345f:	03 54 24 f4          	add    -0xc(%rsp),%edx
    3463:	48 63 db             	movslq %ebx,%rbx
    3466:	44 01 f2             	add    %r14d,%edx
    3469:	41 80 7c 1c ff 07    	cmpb   $0x7,-0x1(%r12,%rbx,1)
    346f:	48 63 d2             	movslq %edx,%rdx
    3472:	41 0f 96 c3          	setbe  %r11b
    3476:	41 80 7c 1c 01 07    	cmpb   $0x7,0x1(%r12,%rbx,1)
    347c:	0f 96 c3             	setbe  %bl
    347f:	41 09 db             	or     %ebx,%r11d
    3482:	45 21 c3             	and    %r8d,%r11d
    3485:	41 80 7c 0c fe 07    	cmpb   $0x7,-0x2(%r12,%rcx,1)
    348b:	41 0f 96 c0          	setbe  %r8b
    348f:	41 80 7c 04 fe 07    	cmpb   $0x7,-0x2(%r12,%rax,1)
    3495:	0f 96 c3             	setbe  %bl
    3498:	41 09 d8             	or     %ebx,%r8d
    349b:	45 21 d0             	and    %r10d,%r8d
    349e:	45 09 d8             	or     %r11d,%r8d
    34a1:	41 80 7c 0c 02 07    	cmpb   $0x7,0x2(%r12,%rcx,1)
    34a7:	0f 96 c1             	setbe  %cl
    34aa:	41 80 7c 04 02 07    	cmpb   $0x7,0x2(%r12,%rax,1)
    34b0:	0f 96 c0             	setbe  %al
    34b3:	09 c1                	or     %eax,%ecx
    34b5:	21 f9                	and    %edi,%ecx
    34b7:	44 08 c1             	or     %r8b,%cl
    34ba:	75 24                	jne    34e0 <susan_thin+0x4f0>
    34bc:	41 80 7c 14 ff 07    	cmpb   $0x7,-0x1(%r12,%rdx,1)
    34c2:	0f 96 c0             	setbe  %al
    34c5:	41 80 7c 14 01 07    	cmpb   $0x7,0x1(%r12,%rdx,1)
    34cb:	0f 96 c2             	setbe  %dl
    34ce:	09 d0                	or     %edx,%eax
    34d0:	44 84 c8             	test   %r9b,%al
    34d3:	0f 84 bf fb ff ff    	je     3098 <susan_thin+0xa8>
    34d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    34e0:	c6 06 64             	movb   $0x64,(%rsi)
    34e3:	8b 74 24 b8          	mov    -0x48(%rsp),%esi
    34e7:	b8 04 00 00 00       	mov    $0x4,%eax
    34ec:	39 c6                	cmp    %eax,%esi
    34ee:	41 89 f5             	mov    %esi,%r13d
    34f1:	44 0f 4c e8          	cmovl  %eax,%r13d
    34f5:	41 83 ee 02          	sub    $0x2,%r14d
    34f9:	e9 52 fe ff ff       	jmp    3350 <susan_thin+0x360>
    34fe:	8b 5c 24 e0          	mov    -0x20(%rsp),%ebx
    3502:	41 80 3c 0c 07       	cmpb   $0x7,(%r12,%rcx,1)
    3507:	40 0f 96 c7          	setbe  %dil
    350b:	41 80 7c 14 01 07    	cmpb   $0x7,0x1(%r12,%rdx,1)
    3511:	44 8d 44 1d 00       	lea    0x0(%rbp,%rbx,1),%r8d
    3516:	41 0f 96 c2          	setbe  %r10b
    351a:	44 0f b6 df          	movzbl %dil,%r11d
    351e:	45 01 f0             	add    %r14d,%r8d
    3521:	41 0f b6 da          	movzbl %r10b,%ebx
    3525:	4d 63 c0             	movslq %r8d,%r8
    3528:	43 80 3c 04 07       	cmpb   $0x7,(%r12,%r8,1)
    352d:	41 0f 96 c1          	setbe  %r9b
    3531:	41 80 7c 14 ff 07    	cmpb   $0x7,-0x1(%r12,%rdx,1)
    3537:	0f 96 c2             	setbe  %dl
    353a:	44 01 db             	add    %r11d,%ebx
    353d:	45 0f b6 d9          	movzbl %r9b,%r11d
    3541:	41 01 db             	add    %ebx,%r11d
    3544:	0f b6 da             	movzbl %dl,%ebx
    3547:	41 01 db             	add    %ebx,%r11d
    354a:	41 83 fb 01          	cmp    $0x1,%r11d
    354e:	0f 8e 44 fb ff ff    	jle    3098 <susan_thin+0xa8>
    3554:	80 38 07             	cmpb   $0x7,(%rax)
    3557:	41 0f 96 c3          	setbe  %r11b
    355b:	41 09 fb             	or     %edi,%r11d
    355e:	41 80 7c 0c 01 07    	cmpb   $0x7,0x1(%r12,%rcx,1)
    3564:	0f 96 c3             	setbe  %bl
    3567:	41 0f b6 c3          	movzbl %r11b,%eax
    356b:	44 09 d3             	or     %r10d,%ebx
    356e:	43 80 7c 04 01 07    	cmpb   $0x7,0x1(%r12,%r8,1)
    3574:	0f 96 c1             	setbe  %cl
    3577:	0f b6 eb             	movzbl %bl,%ebp
    357a:	44 09 c9             	or     %r9d,%ecx
    357d:	43 80 7c 04 ff 07    	cmpb   $0x7,-0x1(%r12,%r8,1)
    3583:	41 0f 96 c0          	setbe  %r8b
    3587:	21 df                	and    %ebx,%edi
    3589:	41 21 ca             	and    %ecx,%r10d
    358c:	01 c5                	add    %eax,%ebp
    358e:	41 09 d0             	or     %edx,%r8d
    3591:	40 0f b6 ff          	movzbl %dil,%edi
    3595:	45 0f b6 d2          	movzbl %r10b,%r10d
    3599:	0f b6 c1             	movzbl %cl,%eax
    359c:	45 21 c1             	and    %r8d,%r9d
    359f:	44 01 d7             	add    %r10d,%edi
    35a2:	44 21 da             	and    %r11d,%edx
    35a5:	01 e8                	add    %ebp,%eax
    35a7:	45 0f b6 c9          	movzbl %r9b,%r9d
    35ab:	41 0f b6 e8          	movzbl %r8b,%ebp
    35af:	0f b6 d2             	movzbl %dl,%edx
    35b2:	44 01 cf             	add    %r9d,%edi
    35b5:	01 e8                	add    %ebp,%eax
    35b7:	01 fa                	add    %edi,%edx
    35b9:	29 d0                	sub    %edx,%eax
    35bb:	83 f8 01             	cmp    $0x1,%eax
    35be:	0f 8f d4 fa ff ff    	jg     3098 <susan_thin+0xa8>
    35c4:	e9 17 ff ff ff       	jmp    34e0 <susan_thin+0x4f0>
    35c9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    35d0:	44 0a 4c 24 bc       	or     -0x44(%rsp),%r9b
    35d5:	0f 84 19 fe ff ff    	je     33f4 <susan_thin+0x404>
    35db:	44 0a 54 24 c0       	or     -0x40(%rsp),%r10b
    35e0:	0f 84 0e fe ff ff    	je     33f4 <susan_thin+0x404>
    35e6:	80 7c 24 b7 07       	cmpb   $0x7,-0x49(%rsp)
    35eb:	0f 87 af 00 00 00    	ja     36a0 <susan_thin+0x6b0>
    35f1:	bf fe ff ff ff       	mov    $0xfffffffe,%edi
    35f6:	41 80 fb 07          	cmp    $0x7,%r11b
    35fa:	0f 87 6e 01 00 00    	ja     376e <susan_thin+0x77e>
    3600:	48 8b 44 24 a8       	mov    -0x58(%rsp),%rax
    3605:	66 0f ef c0          	pxor   %xmm0,%xmm0
    3609:	66 0f ef d2          	pxor   %xmm2,%xmm2
    360d:	f3 0f 2a 54 24 c8    	cvtsi2ssl -0x38(%rsp),%xmm2
    3613:	f3 0f 2a 04 88       	cvtsi2ssl (%rax,%rcx,4),%xmm0
    3618:	f3 0f 5e c2          	divss  %xmm2,%xmm0
    361c:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    3620:	66 0f 2f c1          	comisd %xmm1,%xmm0
    3624:	0f 86 6e fa ff ff    	jbe    3098 <susan_thin+0xa8>
    362a:	41 8d 44 3d 00       	lea    0x0(%r13,%rdi,1),%eax
    362f:	0f af 44 24 a4       	imul   -0x5c(%rsp),%eax
    3634:	44 01 f0             	add    %r14d,%eax
    3637:	48 98                	cltq   
    3639:	41 80 3c 04 07       	cmpb   $0x7,(%r12,%rax,1)
    363e:	0f 86 54 fa ff ff    	jbe    3098 <susan_thin+0xa8>
    3644:	41 80 7c 04 ff 07    	cmpb   $0x7,-0x1(%r12,%rax,1)
    364a:	0f 86 48 fa ff ff    	jbe    3098 <susan_thin+0xa8>
    3650:	41 80 7c 04 01 07    	cmpb   $0x7,0x1(%r12,%rax,1)
    3656:	0f 86 3c fa ff ff    	jbe    3098 <susan_thin+0xa8>
    365c:	c6 06 64             	movb   $0x64,(%rsi)
    365f:	41 c6 04 0c 03       	movb   $0x3,(%r12,%rcx,1)
    3664:	e9 2f fa ff ff       	jmp    3098 <susan_thin+0xa8>
    3669:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    3670:	41 80 3c 0c 07       	cmpb   $0x7,(%r12,%rcx,1)
    3675:	0f 87 a5 00 00 00    	ja     3720 <susan_thin+0x730>
    367b:	d1 64 24 b8          	shll   -0x48(%rsp)
    367f:	45 01 db             	add    %r11d,%r11d
    3682:	8d 1c 5b             	lea    (%rbx,%rbx,2),%ebx
    3685:	41 c1 e2 02          	shl    $0x2,%r10d
    3689:	c7 44 24 bc 00 00 00 	movl   $0x0,-0x44(%rsp)
    3690:	00 
    3691:	47 8d 0c 49          	lea    (%r9,%r9,2),%r9d
    3695:	45 31 c0             	xor    %r8d,%r8d
    3698:	e9 96 fb ff ff       	jmp    3233 <susan_thin+0x243>
    369d:	0f 1f 00             	nopl   (%rax)
    36a0:	48 89 c1             	mov    %rax,%rcx
    36a3:	41 80 fb 07          	cmp    $0x7,%r11b
    36a7:	0f 87 53 ff ff ff    	ja     3600 <susan_thin+0x610>
    36ad:	b9 01 00 00 00       	mov    $0x1,%ecx
    36b2:	44 01 c1             	add    %r8d,%ecx
    36b5:	48 8b 44 24 a8       	mov    -0x58(%rsp),%rax
    36ba:	66 0f ef c0          	pxor   %xmm0,%xmm0
    36be:	66 0f ef d2          	pxor   %xmm2,%xmm2
    36c2:	48 63 c9             	movslq %ecx,%rcx
    36c5:	f3 0f 2a 54 24 c8    	cvtsi2ssl -0x38(%rsp),%xmm2
    36cb:	f3 0f 2a 04 88       	cvtsi2ssl (%rax,%rcx,4),%xmm0
    36d0:	f3 0f 5e c2          	divss  %xmm2,%xmm0
    36d4:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    36d8:	66 0f 2f c1          	comisd %xmm1,%xmm0
    36dc:	0f 86 b6 f9 ff ff    	jbe    3098 <susan_thin+0xa8>
    36e2:	41 8d 04 38          	lea    (%r8,%rdi,1),%eax
    36e6:	48 98                	cltq   
    36e8:	41 80 3c 04 07       	cmpb   $0x7,(%r12,%rax,1)
    36ed:	0f 86 a5 f9 ff ff    	jbe    3098 <susan_thin+0xa8>
    36f3:	8b 44 24 f0          	mov    -0x10(%rsp),%eax
    36f7:	01 f8                	add    %edi,%eax
    36f9:	48 98                	cltq   
    36fb:	41 80 3c 04 07       	cmpb   $0x7,(%r12,%rax,1)
    3700:	0f 86 92 f9 ff ff    	jbe    3098 <susan_thin+0xa8>
    3706:	42 8d 44 35 00       	lea    0x0(%rbp,%r14,1),%eax
    370b:	01 f8                	add    %edi,%eax
    370d:	48 98                	cltq   
    370f:	41 80 3c 04 07       	cmpb   $0x7,(%r12,%rax,1)
    3714:	0f 86 7e f9 ff ff    	jbe    3098 <susan_thin+0xa8>
    371a:	e9 3d ff ff ff       	jmp    365c <susan_thin+0x66c>
    371f:	90                   	nop
    3720:	48 8b 4c 24 c8       	mov    -0x38(%rsp),%rcx
    3725:	41 80 3c 0c 07       	cmpb   $0x7,(%r12,%rcx,1)
    372a:	77 4c                	ja     3778 <susan_thin+0x788>
    372c:	8b 74 24 b8          	mov    -0x48(%rsp),%esi
    3730:	01 c0                	add    %eax,%eax
    3732:	45 01 c9             	add    %r9d,%r9d
    3735:	47 8d 14 52          	lea    (%r10,%r10,2),%r10d
    3739:	c7 44 24 bc 00 00 00 	movl   $0x0,-0x44(%rsp)
    3740:	00 
    3741:	c1 e3 02             	shl    $0x2,%ebx
    3744:	45 31 db             	xor    %r11d,%r11d
    3747:	45 31 c0             	xor    %r8d,%r8d
    374a:	8d 34 76             	lea    (%rsi,%rsi,2),%esi
    374d:	89 74 24 b8          	mov    %esi,-0x48(%rsp)
    3751:	85 c0                	test   %eax,%eax
    3753:	0f 8e da fa ff ff    	jle    3233 <susan_thin+0x243>
    3759:	c7 44 24 e8 00 00 00 	movl   $0x0,-0x18(%rsp)
    3760:	00 
    3761:	c7 44 24 e4 00 00 00 	movl   $0x0,-0x1c(%rsp)
    3768:	00 
    3769:	e9 c7 fa ff ff       	jmp    3235 <susan_thin+0x245>
    376e:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3773:	e9 3a ff ff ff       	jmp    36b2 <susan_thin+0x6c2>
    3778:	41 80 7c 14 ff 07    	cmpb   $0x7,-0x1(%r12,%rdx,1)
    377e:	76 25                	jbe    37a5 <susan_thin+0x7b5>
    3780:	41 80 7c 14 01 07    	cmpb   $0x7,0x1(%r12,%rdx,1)
    3786:	77 3f                	ja     37c7 <susan_thin+0x7d7>
    3788:	d1 64 24 bc          	shll   -0x44(%rsp)
    378c:	45 01 d2             	add    %r10d,%r10d
    378f:	8d 04 40             	lea    (%rax,%rax,2),%eax
    3792:	45 31 c9             	xor    %r9d,%r9d
    3795:	8d 1c 5b             	lea    (%rbx,%rbx,2),%ebx
    3798:	c1 64 24 b8 02       	shll   $0x2,-0x48(%rsp)
    379d:	45 31 db             	xor    %r11d,%r11d
    37a0:	45 31 c0             	xor    %r8d,%r8d
    37a3:	eb ac                	jmp    3751 <susan_thin+0x761>
    37a5:	d1 64 24 bc          	shll   -0x44(%rsp)
    37a9:	45 01 d2             	add    %r10d,%r10d
    37ac:	47 8d 04 40          	lea    (%r8,%r8,2),%r8d
    37b0:	41 c1 e3 02          	shl    $0x2,%r11d
    37b4:	c7 44 24 b8 00 00 00 	movl   $0x0,-0x48(%rsp)
    37bb:	00 
    37bc:	47 8d 0c 49          	lea    (%r9,%r9,2),%r9d
    37c0:	31 db                	xor    %ebx,%ebx
    37c2:	e9 6c fa ff ff       	jmp    3233 <susan_thin+0x243>
    37c7:	41 80 7c 34 ff 07    	cmpb   $0x7,-0x1(%r12,%rsi,1)
    37cd:	76 27                	jbe    37f6 <susan_thin+0x806>
    37cf:	41 80 3c 34 07       	cmpb   $0x7,(%r12,%rsi,1)
    37d4:	77 4a                	ja     3820 <susan_thin+0x830>
    37d6:	d1 64 24 b8          	shll   -0x48(%rsp)
    37da:	45 01 db             	add    %r11d,%r11d
    37dd:	8d 04 40             	lea    (%rax,%rax,2),%eax
    37e0:	45 31 c9             	xor    %r9d,%r9d
    37e3:	47 8d 04 40          	lea    (%r8,%r8,2),%r8d
    37e7:	c1 64 24 bc 02       	shll   $0x2,-0x44(%rsp)
    37ec:	45 31 d2             	xor    %r10d,%r10d
    37ef:	31 db                	xor    %ebx,%ebx
    37f1:	e9 5b ff ff ff       	jmp    3751 <susan_thin+0x761>
    37f6:	8b 74 24 bc          	mov    -0x44(%rsp),%esi
    37fa:	c7 44 24 b8 00 00 00 	movl   $0x0,-0x48(%rsp)
    3801:	00 
    3802:	01 c0                	add    %eax,%eax
    3804:	31 db                	xor    %ebx,%ebx
    3806:	45 01 c9             	add    %r9d,%r9d
    3809:	47 8d 1c 5b          	lea    (%r11,%r11,2),%r11d
    380d:	41 c1 e0 02          	shl    $0x2,%r8d
    3811:	45 31 d2             	xor    %r10d,%r10d
    3814:	8d 34 76             	lea    (%rsi,%rsi,2),%esi
    3817:	89 74 24 bc          	mov    %esi,-0x44(%rsp)
    381b:	e9 31 ff ff ff       	jmp    3751 <susan_thin+0x761>
    3820:	41 80 7c 34 01 07    	cmpb   $0x7,0x1(%r12,%rsi,1)
    3826:	0f 87 25 ff ff ff    	ja     3751 <susan_thin+0x761>
    382c:	8b 74 24 bc          	mov    -0x44(%rsp),%esi
    3830:	01 db                	add    %ebx,%ebx
    3832:	45 01 c0             	add    %r8d,%r8d
    3835:	c1 e0 02             	shl    $0x2,%eax
    3838:	45 31 c9             	xor    %r9d,%r9d
    383b:	45 31 d2             	xor    %r10d,%r10d
    383e:	45 31 db             	xor    %r11d,%r11d
    3841:	8d 34 76             	lea    (%rsi,%rsi,2),%esi
    3844:	89 74 24 bc          	mov    %esi,-0x44(%rsp)
    3848:	8b 74 24 b8          	mov    -0x48(%rsp),%esi
    384c:	8d 34 76             	lea    (%rsi,%rsi,2),%esi
    384f:	89 74 24 b8          	mov    %esi,-0x48(%rsp)
    3853:	e9 f9 fe ff ff       	jmp    3751 <susan_thin+0x761>
    3858:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    385f:	00 

0000000000003860 <susan_edges>:
    3860:	f3 0f 1e fa          	endbr64 
    3864:	41 57                	push   %r15
    3866:	49 89 f7             	mov    %rsi,%r15
    3869:	41 56                	push   %r14
    386b:	41 55                	push   %r13
    386d:	41 54                	push   %r12
    386f:	55                   	push   %rbp
    3870:	48 89 fd             	mov    %rdi,%rbp
    3873:	53                   	push   %rbx
    3874:	44 89 cb             	mov    %r9d,%ebx
    3877:	48 81 ec d8 01 00 00 	sub    $0x1d8,%rsp
    387e:	48 89 54 24 40       	mov    %rdx,0x40(%rsp)
    3883:	8b 94 24 10 02 00 00 	mov    0x210(%rsp),%edx
    388a:	48 89 bc 24 f0 00 00 	mov    %rdi,0xf0(%rsp)
    3891:	00 
    3892:	4c 89 ff             	mov    %r15,%rdi
    3895:	41 0f af d1          	imul   %r9d,%edx
    3899:	48 89 b4 24 30 01 00 	mov    %rsi,0x130(%rsp)
    38a0:	00 
    38a1:	31 f6                	xor    %esi,%esi
    38a3:	48 89 8c 24 28 01 00 	mov    %rcx,0x128(%rsp)
    38aa:	00 
    38ab:	44 89 84 24 38 01 00 	mov    %r8d,0x138(%rsp)
    38b2:	00 
    38b3:	48 63 d2             	movslq %edx,%rdx
    38b6:	44 89 8c 24 3c 01 00 	mov    %r9d,0x13c(%rsp)
    38bd:	00 
    38be:	48 c1 e2 02          	shl    $0x2,%rdx
    38c2:	e8 19 d9 ff ff       	call   11e0 <memset@plt>
    38c7:	8b 84 24 10 02 00 00 	mov    0x210(%rsp),%eax
    38ce:	83 e8 03             	sub    $0x3,%eax
    38d1:	89 44 24 48          	mov    %eax,0x48(%rsp)
    38d5:	83 f8 03             	cmp    $0x3,%eax
    38d8:	0f 8e 86 03 00 00    	jle    3c64 <susan_edges+0x404>
    38de:	89 de                	mov    %ebx,%esi
    38e0:	83 fb 06             	cmp    $0x6,%ebx
    38e3:	0f 8e 7b 03 00 00    	jle    3c64 <susan_edges+0x404>
    38e9:	4c 63 c3             	movslq %ebx,%r8
    38ec:	8d 14 76             	lea    (%rsi,%rsi,2),%edx
    38ef:	44 8d 66 f9          	lea    -0x7(%rsi),%r12d
    38f3:	41 be 03 00 00 00    	mov    $0x3,%r14d
    38f9:	4b 8d 1c 00          	lea    (%r8,%r8,1),%rbx
    38fd:	48 63 d2             	movslq %edx,%rdx
    3900:	44 89 74 24 0c       	mov    %r14d,0xc(%rsp)
    3905:	49 83 c4 04          	add    $0x4,%r12
    3909:	4d 8d 2c 97          	lea    (%r15,%rdx,4),%r13
    390d:	4a 8d 04 03          	lea    (%rbx,%r8,1),%rax
    3911:	ba 02 00 00 00       	mov    $0x2,%edx
    3916:	48 89 5c 24 20       	mov    %rbx,0x20(%rsp)
    391b:	4a 8d 3c 85 00 00 00 	lea    0x0(,%r8,4),%rdi
    3922:	00 
    3923:	48 29 c2             	sub    %rax,%rdx
    3926:	4c 89 2c 24          	mov    %r13,(%rsp)
    392a:	4c 8b b4 24 28 01 00 	mov    0x128(%rsp),%r14
    3931:	00 
    3932:	48 89 7c 24 18       	mov    %rdi,0x18(%rsp)
    3937:	49 8d 78 01          	lea    0x1(%r8),%rdi
    393b:	44 8b ac 24 38 01 00 	mov    0x138(%rsp),%r13d
    3942:	00 
    3943:	48 01 c5             	add    %rax,%rbp
    3946:	48 89 7c 24 30       	mov    %rdi,0x30(%rsp)
    394b:	48 8d 7b 02          	lea    0x2(%rbx),%rdi
    394f:	48 89 7c 24 38       	mov    %rdi,0x38(%rsp)
    3954:	48 89 54 24 28       	mov    %rdx,0x28(%rsp)
    3959:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    3960:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    3965:	48 89 ee             	mov    %rbp,%rsi
    3968:	4c 8d 4d 01          	lea    0x1(%rbp),%r9
    396c:	41 ba 03 00 00 00    	mov    $0x3,%r10d
    3972:	4c 29 c6             	sub    %r8,%rsi
    3975:	48 8d 0c 28          	lea    (%rax,%rbp,1),%rcx
    3979:	48 8b 44 24 30       	mov    0x30(%rsp),%rax
    397e:	48 89 74 24 10       	mov    %rsi,0x10(%rsp)
    3983:	48 8d 3c 28          	lea    (%rax,%rbp,1),%rdi
    3987:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    398c:	48 8d 14 28          	lea    (%rax,%rbp,1),%rdx
    3990:	42 0f b6 44 15 00    	movzbl 0x0(%rbp,%r10,1),%eax
    3996:	0f b6 19             	movzbl (%rcx),%ebx
    3999:	44 0f b6 79 01       	movzbl 0x1(%rcx),%r15d
    399e:	4c 01 f0             	add    %r14,%rax
    39a1:	49 89 c3             	mov    %rax,%r11
    39a4:	49 29 db             	sub    %rbx,%r11
    39a7:	48 89 c3             	mov    %rax,%rbx
    39aa:	4c 29 fb             	sub    %r15,%rbx
    39ad:	45 0f b6 1b          	movzbl (%r11),%r11d
    39b1:	44 0f b6 79 02       	movzbl 0x2(%rcx),%r15d
    39b6:	0f b6 1b             	movzbl (%rbx),%ebx
    39b9:	45 8d 5c 1b 64       	lea    0x64(%r11,%rbx,1),%r11d
    39be:	48 89 c3             	mov    %rax,%rbx
    39c1:	4c 29 fb             	sub    %r15,%rbx
    39c4:	46 0f b6 7c 01 ff    	movzbl -0x1(%rcx,%r8,1),%r15d
    39ca:	0f b6 1b             	movzbl (%rbx),%ebx
    39cd:	44 01 db             	add    %r11d,%ebx
    39d0:	49 89 c3             	mov    %rax,%r11
    39d3:	4d 29 fb             	sub    %r15,%r11
    39d6:	46 0f b6 3c 01       	movzbl (%rcx,%r8,1),%r15d
    39db:	45 0f b6 1b          	movzbl (%r11),%r11d
    39df:	41 01 db             	add    %ebx,%r11d
    39e2:	48 89 c3             	mov    %rax,%rbx
    39e5:	4c 29 fb             	sub    %r15,%rbx
    39e8:	46 0f b6 7c 01 01    	movzbl 0x1(%rcx,%r8,1),%r15d
    39ee:	0f b6 1b             	movzbl (%rbx),%ebx
    39f1:	44 01 db             	add    %r11d,%ebx
    39f4:	49 89 c3             	mov    %rax,%r11
    39f7:	4d 29 fb             	sub    %r15,%r11
    39fa:	46 0f b6 7c 01 02    	movzbl 0x2(%rcx,%r8,1),%r15d
    3a00:	45 0f b6 1b          	movzbl (%r11),%r11d
    3a04:	41 01 db             	add    %ebx,%r11d
    3a07:	48 89 c3             	mov    %rax,%rbx
    3a0a:	4c 29 fb             	sub    %r15,%rbx
    3a0d:	46 0f b6 7c 01 03    	movzbl 0x3(%rcx,%r8,1),%r15d
    3a13:	0f b6 1b             	movzbl (%rbx),%ebx
    3a16:	44 01 db             	add    %r11d,%ebx
    3a19:	49 89 c3             	mov    %rax,%r11
    3a1c:	4d 29 fb             	sub    %r15,%r11
    3a1f:	44 0f b6 3e          	movzbl (%rsi),%r15d
    3a23:	45 0f b6 1b          	movzbl (%r11),%r11d
    3a27:	41 01 db             	add    %ebx,%r11d
    3a2a:	48 89 c3             	mov    %rax,%rbx
    3a2d:	4c 29 fb             	sub    %r15,%rbx
    3a30:	44 0f b6 7e 01       	movzbl 0x1(%rsi),%r15d
    3a35:	0f b6 1b             	movzbl (%rbx),%ebx
    3a38:	44 01 db             	add    %r11d,%ebx
    3a3b:	49 89 c3             	mov    %rax,%r11
    3a3e:	4d 29 fb             	sub    %r15,%r11
    3a41:	44 0f b6 7e 02       	movzbl 0x2(%rsi),%r15d
    3a46:	45 0f b6 1b          	movzbl (%r11),%r11d
    3a4a:	41 01 db             	add    %ebx,%r11d
    3a4d:	48 89 c3             	mov    %rax,%rbx
    3a50:	4c 29 fb             	sub    %r15,%rbx
    3a53:	44 0f b6 7e 03       	movzbl 0x3(%rsi),%r15d
    3a58:	0f b6 1b             	movzbl (%rbx),%ebx
    3a5b:	44 01 db             	add    %r11d,%ebx
    3a5e:	49 89 c3             	mov    %rax,%r11
    3a61:	4d 29 fb             	sub    %r15,%r11
    3a64:	44 0f b6 7e 04       	movzbl 0x4(%rsi),%r15d
    3a69:	45 0f b6 1b          	movzbl (%r11),%r11d
    3a6d:	41 01 db             	add    %ebx,%r11d
    3a70:	48 89 c3             	mov    %rax,%rbx
    3a73:	4c 29 fb             	sub    %r15,%rbx
    3a76:	44 0f b6 7e 05       	movzbl 0x5(%rsi),%r15d
    3a7b:	0f b6 1b             	movzbl (%rbx),%ebx
    3a7e:	44 01 db             	add    %r11d,%ebx
    3a81:	49 89 c3             	mov    %rax,%r11
    3a84:	4d 29 fb             	sub    %r15,%r11
    3a87:	44 0f b6 7e 06       	movzbl 0x6(%rsi),%r15d
    3a8c:	45 0f b6 1b          	movzbl (%r11),%r11d
    3a90:	41 01 db             	add    %ebx,%r11d
    3a93:	48 89 c3             	mov    %rax,%rbx
    3a96:	4c 29 fb             	sub    %r15,%rbx
    3a99:	45 0f b6 79 ff       	movzbl -0x1(%r9),%r15d
    3a9e:	0f b6 1b             	movzbl (%rbx),%ebx
    3aa1:	44 01 db             	add    %r11d,%ebx
    3aa4:	49 89 c3             	mov    %rax,%r11
    3aa7:	4d 29 fb             	sub    %r15,%r11
    3aaa:	45 0f b6 1b          	movzbl (%r11),%r11d
    3aae:	45 0f b6 39          	movzbl (%r9),%r15d
    3ab2:	41 01 db             	add    %ebx,%r11d
    3ab5:	48 89 c3             	mov    %rax,%rbx
    3ab8:	4c 29 fb             	sub    %r15,%rbx
    3abb:	45 0f b6 79 01       	movzbl 0x1(%r9),%r15d
    3ac0:	0f b6 1b             	movzbl (%rbx),%ebx
    3ac3:	44 01 db             	add    %r11d,%ebx
    3ac6:	49 89 c3             	mov    %rax,%r11
    3ac9:	4d 29 fb             	sub    %r15,%r11
    3acc:	45 0f b6 79 03       	movzbl 0x3(%r9),%r15d
    3ad1:	45 0f b6 1b          	movzbl (%r11),%r11d
    3ad5:	41 01 db             	add    %ebx,%r11d
    3ad8:	48 89 c3             	mov    %rax,%rbx
    3adb:	4c 29 fb             	sub    %r15,%rbx
    3ade:	45 0f b6 79 04       	movzbl 0x4(%r9),%r15d
    3ae3:	0f b6 1b             	movzbl (%rbx),%ebx
    3ae6:	44 01 db             	add    %r11d,%ebx
    3ae9:	49 89 c3             	mov    %rax,%r11
    3aec:	4d 29 fb             	sub    %r15,%r11
    3aef:	45 0f b6 79 05       	movzbl 0x5(%r9),%r15d
    3af4:	45 0f b6 1b          	movzbl (%r11),%r11d
    3af8:	41 01 db             	add    %ebx,%r11d
    3afb:	48 89 c3             	mov    %rax,%rbx
    3afe:	4c 29 fb             	sub    %r15,%rbx
    3b01:	44 0f b6 7f ff       	movzbl -0x1(%rdi),%r15d
    3b06:	0f b6 1b             	movzbl (%rbx),%ebx
    3b09:	44 01 db             	add    %r11d,%ebx
    3b0c:	49 89 c3             	mov    %rax,%r11
    3b0f:	4d 29 fb             	sub    %r15,%r11
    3b12:	44 0f b6 3f          	movzbl (%rdi),%r15d
    3b16:	45 0f b6 1b          	movzbl (%r11),%r11d
    3b1a:	41 01 db             	add    %ebx,%r11d
    3b1d:	48 89 c3             	mov    %rax,%rbx
    3b20:	4c 29 fb             	sub    %r15,%rbx
    3b23:	44 0f b6 7f 01       	movzbl 0x1(%rdi),%r15d
    3b28:	0f b6 1b             	movzbl (%rbx),%ebx
    3b2b:	44 01 db             	add    %r11d,%ebx
    3b2e:	49 89 c3             	mov    %rax,%r11
    3b31:	4d 29 fb             	sub    %r15,%r11
    3b34:	44 0f b6 7f 02       	movzbl 0x2(%rdi),%r15d
    3b39:	45 0f b6 1b          	movzbl (%r11),%r11d
    3b3d:	41 01 db             	add    %ebx,%r11d
    3b40:	48 89 c3             	mov    %rax,%rbx
    3b43:	4c 29 fb             	sub    %r15,%rbx
    3b46:	44 0f b6 7f 03       	movzbl 0x3(%rdi),%r15d
    3b4b:	0f b6 1b             	movzbl (%rbx),%ebx
    3b4e:	44 01 db             	add    %r11d,%ebx
    3b51:	49 89 c3             	mov    %rax,%r11
    3b54:	4d 29 fb             	sub    %r15,%r11
    3b57:	44 0f b6 7f 04       	movzbl 0x4(%rdi),%r15d
    3b5c:	45 0f b6 1b          	movzbl (%r11),%r11d
    3b60:	41 01 db             	add    %ebx,%r11d
    3b63:	48 89 c3             	mov    %rax,%rbx
    3b66:	4c 29 fb             	sub    %r15,%rbx
    3b69:	44 0f b6 7f 05       	movzbl 0x5(%rdi),%r15d
    3b6e:	0f b6 1b             	movzbl (%rbx),%ebx
    3b71:	44 01 db             	add    %r11d,%ebx
    3b74:	49 89 c3             	mov    %rax,%r11
    3b77:	4d 29 fb             	sub    %r15,%r11
    3b7a:	44 0f b6 7a ff       	movzbl -0x1(%rdx),%r15d
    3b7f:	45 0f b6 1b          	movzbl (%r11),%r11d
    3b83:	41 01 db             	add    %ebx,%r11d
    3b86:	48 89 c3             	mov    %rax,%rbx
    3b89:	4c 29 fb             	sub    %r15,%rbx
    3b8c:	44 0f b6 3a          	movzbl (%rdx),%r15d
    3b90:	0f b6 1b             	movzbl (%rbx),%ebx
    3b93:	44 01 db             	add    %r11d,%ebx
    3b96:	49 89 c3             	mov    %rax,%r11
    3b99:	4d 29 fb             	sub    %r15,%r11
    3b9c:	44 0f b6 7a 01       	movzbl 0x1(%rdx),%r15d
    3ba1:	45 0f b6 1b          	movzbl (%r11),%r11d
    3ba5:	41 01 db             	add    %ebx,%r11d
    3ba8:	48 89 c3             	mov    %rax,%rbx
    3bab:	4c 29 fb             	sub    %r15,%rbx
    3bae:	44 0f b6 7a 02       	movzbl 0x2(%rdx),%r15d
    3bb3:	0f b6 1b             	movzbl (%rbx),%ebx
    3bb6:	44 01 db             	add    %r11d,%ebx
    3bb9:	49 89 c3             	mov    %rax,%r11
    3bbc:	4d 29 fb             	sub    %r15,%r11
    3bbf:	45 0f b6 1b          	movzbl (%r11),%r11d
    3bc3:	44 0f b6 7a 03       	movzbl 0x3(%rdx),%r15d
    3bc8:	41 01 db             	add    %ebx,%r11d
    3bcb:	48 89 c3             	mov    %rax,%rbx
    3bce:	4c 29 fb             	sub    %r15,%rbx
    3bd1:	46 0f b6 3c 02       	movzbl (%rdx,%r8,1),%r15d
    3bd6:	0f b6 1b             	movzbl (%rbx),%ebx
    3bd9:	44 01 db             	add    %r11d,%ebx
    3bdc:	49 89 c3             	mov    %rax,%r11
    3bdf:	4d 29 fb             	sub    %r15,%r11
    3be2:	46 0f b6 7c 02 01    	movzbl 0x1(%rdx,%r8,1),%r15d
    3be8:	45 0f b6 1b          	movzbl (%r11),%r11d
    3bec:	41 01 db             	add    %ebx,%r11d
    3bef:	48 89 c3             	mov    %rax,%rbx
    3bf2:	4c 29 fb             	sub    %r15,%rbx
    3bf5:	0f b6 1b             	movzbl (%rbx),%ebx
    3bf8:	41 01 db             	add    %ebx,%r11d
    3bfb:	42 0f b6 5c 02 02    	movzbl 0x2(%rdx,%r8,1),%ebx
    3c01:	48 29 d8             	sub    %rbx,%rax
    3c04:	0f b6 00             	movzbl (%rax),%eax
    3c07:	44 01 d8             	add    %r11d,%eax
    3c0a:	41 39 c5             	cmp    %eax,%r13d
    3c0d:	7c 0e                	jl     3c1d <susan_edges+0x3bd>
    3c0f:	45 89 eb             	mov    %r13d,%r11d
    3c12:	41 29 c3             	sub    %eax,%r11d
    3c15:	48 8b 04 24          	mov    (%rsp),%rax
    3c19:	46 89 1c 90          	mov    %r11d,(%rax,%r10,4)
    3c1d:	49 83 c2 01          	add    $0x1,%r10
    3c21:	48 83 c1 01          	add    $0x1,%rcx
    3c25:	48 83 c6 01          	add    $0x1,%rsi
    3c29:	49 83 c1 01          	add    $0x1,%r9
    3c2d:	48 83 c7 01          	add    $0x1,%rdi
    3c31:	48 83 c2 01          	add    $0x1,%rdx
    3c35:	4d 39 d4             	cmp    %r10,%r12
    3c38:	0f 85 52 fd ff ff    	jne    3990 <susan_edges+0x130>
    3c3e:	83 44 24 0c 01       	addl   $0x1,0xc(%rsp)
    3c43:	48 8b 6c 24 10       	mov    0x10(%rsp),%rbp
    3c48:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
    3c4d:	8b 44 24 0c          	mov    0xc(%rsp),%eax
    3c51:	48 01 34 24          	add    %rsi,(%rsp)
    3c55:	48 03 6c 24 20       	add    0x20(%rsp),%rbp
    3c5a:	3b 44 24 48          	cmp    0x48(%rsp),%eax
    3c5e:	0f 85 fc fc ff ff    	jne    3960 <susan_edges+0x100>
    3c64:	8b 84 24 10 02 00 00 	mov    0x210(%rsp),%eax
    3c6b:	83 e8 04             	sub    $0x4,%eax
    3c6e:	89 84 24 6c 01 00 00 	mov    %eax,0x16c(%rsp)
    3c75:	83 f8 04             	cmp    $0x4,%eax
    3c78:	0f 8e 03 0c 00 00    	jle    4881 <susan_edges+0x1021>
    3c7e:	8b 8c 24 3c 01 00 00 	mov    0x13c(%rsp),%ecx
    3c85:	83 f9 08             	cmp    $0x8,%ecx
    3c88:	0f 8e f3 0b 00 00    	jle    4881 <susan_edges+0x1021>
    3c8e:	8d 04 8d 00 00 00 00 	lea    0x0(,%rcx,4),%eax
    3c95:	48 8b 5c 24 40       	mov    0x40(%rsp),%rbx
    3c9a:	48 63 f1             	movslq %ecx,%rsi
    3c9d:	89 8c 24 5c 01 00 00 	mov    %ecx,0x15c(%rsp)
    3ca4:	48 63 f8             	movslq %eax,%rdi
    3ca7:	01 c8                	add    %ecx,%eax
    3ca9:	48 8d 14 b6          	lea    (%rsi,%rsi,4),%rdx
    3cad:	48 89 b4 24 70 01 00 	mov    %rsi,0x170(%rsp)
    3cb4:	00 
    3cb5:	48 01 fb             	add    %rdi,%rbx
    3cb8:	48 89 bc 24 50 01 00 	mov    %rdi,0x150(%rsp)
    3cbf:	00 
    3cc0:	f3 0f 10 15 f4 39 00 	movss  0x39f4(%rip),%xmm2        # 76bc <_IO_stdin_used+0x6bc>
    3cc7:	00 
    3cc8:	66 0f ef e4          	pxor   %xmm4,%xmm4
    3ccc:	48 89 9c 24 60 01 00 	mov    %rbx,0x160(%rsp)
    3cd3:	00 
    3cd4:	48 8b 9c 24 f0 00 00 	mov    0xf0(%rsp),%rbx
    3cdb:	00 
    3cdc:	89 84 24 4c 01 00 00 	mov    %eax,0x14c(%rsp)
    3ce3:	48 89 f8             	mov    %rdi,%rax
    3ce6:	48 01 fb             	add    %rdi,%rbx
    3ce9:	48 8b bc 24 30 01 00 	mov    0x130(%rsp),%rdi
    3cf0:	00 
    3cf1:	48 89 94 24 88 01 00 	mov    %rdx,0x188(%rsp)
    3cf8:	00 
    3cf9:	48 89 9c 24 f8 00 00 	mov    %rbx,0xf8(%rsp)
    3d00:	00 
    3d01:	c7 84 24 48 01 00 00 	movl   $0x4,0x148(%rsp)
    3d08:	04 00 00 00 
    3d0c:	48 8d 3c 87          	lea    (%rdi,%rax,4),%rdi
    3d10:	48 83 c0 02          	add    $0x2,%rax
    3d14:	48 89 bc 24 b0 00 00 	mov    %rdi,0xb0(%rsp)
    3d1b:	00 
    3d1c:	48 8d 3c 36          	lea    (%rsi,%rsi,1),%rdi
    3d20:	48 89 fb             	mov    %rdi,%rbx
    3d23:	48 89 84 24 98 01 00 	mov    %rax,0x198(%rsp)
    3d2a:	00 
    3d2b:	8d 41 f7             	lea    -0x9(%rcx),%eax
    3d2e:	48 01 f3             	add    %rsi,%rbx
    3d31:	48 83 c6 02          	add    $0x2,%rsi
    3d35:	48 83 c0 05          	add    $0x5,%rax
    3d39:	48 89 bc 24 78 01 00 	mov    %rdi,0x178(%rsp)
    3d40:	00 
    3d41:	48 89 9c 24 80 01 00 	mov    %rbx,0x180(%rsp)
    3d48:	00 
    3d49:	48 01 db             	add    %rbx,%rbx
    3d4c:	48 89 9c 24 90 01 00 	mov    %rbx,0x190(%rsp)
    3d53:	00 
    3d54:	8d 1c 49             	lea    (%rcx,%rcx,2),%ebx
    3d57:	89 9c 24 58 01 00 00 	mov    %ebx,0x158(%rsp)
    3d5e:	83 c3 05             	add    $0x5,%ebx
    3d61:	48 89 b4 24 a0 01 00 	mov    %rsi,0x1a0(%rsp)
    3d68:	00 
    3d69:	48 8d 77 02          	lea    0x2(%rdi),%rsi
    3d6d:	89 9c 24 b0 01 00 00 	mov    %ebx,0x1b0(%rsp)
    3d74:	48 89 b4 24 a8 01 00 	mov    %rsi,0x1a8(%rsp)
    3d7b:	00 
    3d7c:	48 89 84 24 b8 00 00 	mov    %rax,0xb8(%rsp)
    3d83:	00 
    3d84:	0f 1f 40 00          	nopl   0x0(%rax)
    3d88:	8b 84 24 48 01 00 00 	mov    0x148(%rsp),%eax
    3d8f:	8b 8c 24 3c 01 00 00 	mov    0x13c(%rsp),%ecx
    3d96:	41 b9 04 00 00 00    	mov    $0x4,%r9d
    3d9c:	8b b4 24 b0 01 00 00 	mov    0x1b0(%rsp),%esi
    3da3:	f2 0f 10 1d ed 38 00 	movsd  0x38ed(%rip),%xmm3        # 7698 <_IO_stdin_used+0x698>
    3daa:	00 
    3dab:	89 84 24 40 01 00 00 	mov    %eax,0x140(%rsp)
    3db2:	83 c0 01             	add    $0x1,%eax
    3db5:	89 84 24 48 01 00 00 	mov    %eax,0x148(%rsp)
    3dbc:	8b 84 24 58 01 00 00 	mov    0x158(%rsp),%eax
    3dc3:	89 84 24 68 01 00 00 	mov    %eax,0x168(%rsp)
    3dca:	01 c8                	add    %ecx,%eax
    3dcc:	48 63 8c 24 5c 01 00 	movslq 0x15c(%rsp),%rcx
    3dd3:	00 
    3dd4:	89 84 24 58 01 00 00 	mov    %eax,0x158(%rsp)
    3ddb:	8b 84 24 4c 01 00 00 	mov    0x14c(%rsp),%eax
    3de2:	01 ce                	add    %ecx,%esi
    3de4:	48 89 8c 24 00 01 00 	mov    %rcx,0x100(%rsp)
    3deb:	00 
    3dec:	83 c0 04             	add    $0x4,%eax
    3def:	89 74 24 64          	mov    %esi,0x64(%rsp)
    3df3:	48 8b b4 24 f0 00 00 	mov    0xf0(%rsp),%rsi
    3dfa:	00 
    3dfb:	89 44 24 68          	mov    %eax,0x68(%rsp)
    3dff:	48 8b 84 24 a0 01 00 	mov    0x1a0(%rsp),%rax
    3e06:	00 
    3e07:	48 01 c8             	add    %rcx,%rax
    3e0a:	48 8d 3c 06          	lea    (%rsi,%rax,1),%rdi
    3e0e:	48 8b 84 24 a8 01 00 	mov    0x1a8(%rsp),%rax
    3e15:	00 
    3e16:	49 89 fc             	mov    %rdi,%r12
    3e19:	48 01 c8             	add    %rcx,%rax
    3e1c:	4c 8d 34 06          	lea    (%rsi,%rax,1),%r14
    3e20:	48 8b 84 24 98 01 00 	mov    0x198(%rsp),%rax
    3e27:	00 
    3e28:	48 01 c8             	add    %rcx,%rax
    3e2b:	4c 8d 3c 06          	lea    (%rsi,%rax,1),%r15
    3e2f:	48 8b 84 24 78 01 00 	mov    0x178(%rsp),%rax
    3e36:	00 
    3e37:	48 01 c8             	add    %rcx,%rax
    3e3a:	48 01 f0             	add    %rsi,%rax
    3e3d:	48 89 84 24 20 01 00 	mov    %rax,0x120(%rsp)
    3e44:	00 
    3e45:	48 8b 84 24 80 01 00 	mov    0x180(%rsp),%rax
    3e4c:	00 
    3e4d:	48 01 c8             	add    %rcx,%rax
    3e50:	4c 8d 04 06          	lea    (%rsi,%rax,1),%r8
    3e54:	48 8b 84 24 50 01 00 	mov    0x150(%rsp),%rax
    3e5b:	00 
    3e5c:	4d 89 c5             	mov    %r8,%r13
    3e5f:	48 01 c8             	add    %rcx,%rax
    3e62:	48 01 f0             	add    %rsi,%rax
    3e65:	48 89 84 24 18 01 00 	mov    %rax,0x118(%rsp)
    3e6c:	00 
    3e6d:	48 8b 84 24 88 01 00 	mov    0x188(%rsp),%rax
    3e74:	00 
    3e75:	48 01 c8             	add    %rcx,%rax
    3e78:	48 01 f0             	add    %rsi,%rax
    3e7b:	48 89 84 24 10 01 00 	mov    %rax,0x110(%rsp)
    3e82:	00 
    3e83:	48 8b 84 24 90 01 00 	mov    0x190(%rsp),%rax
    3e8a:	00 
    3e8b:	48 01 c8             	add    %rcx,%rax
    3e8e:	48 01 f0             	add    %rsi,%rax
    3e91:	48 89 84 24 08 01 00 	mov    %rax,0x108(%rsp)
    3e98:	00 
    3e99:	e9 aa 00 00 00       	jmp    3f48 <susan_edges+0x6e8>
    3e9e:	66 90                	xchg   %ax,%ax
    3ea0:	8b 44 24 68          	mov    0x68(%rsp),%eax
    3ea4:	31 f6                	xor    %esi,%esi
    3ea6:	bf 02 00 00 00       	mov    $0x2,%edi
    3eab:	b9 01 00 00 00       	mov    $0x1,%ecx
    3eb0:	48 8b 9c 24 30 01 00 	mov    0x130(%rsp),%rbx
    3eb7:	00 
    3eb8:	48 98                	cltq   
    3eba:	44 3b 14 83          	cmp    (%rbx,%rax,4),%r10d
    3ebe:	7e 60                	jle    3f20 <susan_edges+0x6c0>
    3ec0:	44 8b 84 24 40 01 00 	mov    0x140(%rsp),%r8d
    3ec7:	00 
    3ec8:	44 8b 9c 24 3c 01 00 	mov    0x13c(%rsp),%r11d
    3ecf:	00 
    3ed0:	8b 6c 24 70          	mov    0x70(%rsp),%ebp
    3ed4:	44 89 c0             	mov    %r8d,%eax
    3ed7:	29 c8                	sub    %ecx,%eax
    3ed9:	41 0f af c3          	imul   %r11d,%eax
    3edd:	01 e8                	add    %ebp,%eax
    3edf:	29 d0                	sub    %edx,%eax
    3ee1:	48 98                	cltq   
    3ee3:	44 3b 14 83          	cmp    (%rbx,%rax,4),%r10d
    3ee7:	7c 37                	jl     3f20 <susan_edges+0x6c0>
    3ee9:	41 8d 04 38          	lea    (%r8,%rdi,1),%eax
    3eed:	41 0f af c3          	imul   %r11d,%eax
    3ef1:	01 e8                	add    %ebp,%eax
    3ef3:	01 f0                	add    %esi,%eax
    3ef5:	48 98                	cltq   
    3ef7:	44 3b 14 83          	cmp    (%rbx,%rax,4),%r10d
    3efb:	7e 23                	jle    3f20 <susan_edges+0x6c0>
    3efd:	44 89 c0             	mov    %r8d,%eax
    3f00:	29 f8                	sub    %edi,%eax
    3f02:	41 0f af c3          	imul   %r11d,%eax
    3f06:	01 e8                	add    %ebp,%eax
    3f08:	29 f0                	sub    %esi,%eax
    3f0a:	48 98                	cltq   
    3f0c:	44 3b 14 83          	cmp    (%rbx,%rax,4),%r10d
    3f10:	7c 0e                	jl     3f20 <susan_edges+0x6c0>
    3f12:	48 8b 84 24 60 01 00 	mov    0x160(%rsp),%rax
    3f19:	00 
    3f1a:	42 c6 04 08 02       	movb   $0x2,(%rax,%r9,1)
    3f1f:	90                   	nop
    3f20:	49 83 c1 01          	add    $0x1,%r9
    3f24:	49 83 c4 01          	add    $0x1,%r12
    3f28:	49 83 c6 01          	add    $0x1,%r14
    3f2c:	49 83 c7 01          	add    $0x1,%r15
    3f30:	83 44 24 64 01       	addl   $0x1,0x64(%rsp)
    3f35:	83 44 24 68 01       	addl   $0x1,0x68(%rsp)
    3f3a:	4c 39 8c 24 b8 00 00 	cmp    %r9,0xb8(%rsp)
    3f41:	00 
    3f42:	0f 84 e8 08 00 00    	je     4830 <susan_edges+0xfd0>
    3f48:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    3f4f:	00 
    3f50:	44 89 8c 24 c0 00 00 	mov    %r9d,0xc0(%rsp)
    3f57:	00 
    3f58:	44 89 4c 24 70       	mov    %r9d,0x70(%rsp)
    3f5d:	46 8b 14 88          	mov    (%rax,%r9,4),%r10d
    3f61:	45 85 d2             	test   %r10d,%r10d
    3f64:	7e ba                	jle    3f20 <susan_edges+0x6c0>
    3f66:	8b 84 24 38 01 00 00 	mov    0x138(%rsp),%eax
    3f6d:	48 8b 8c 24 f8 00 00 	mov    0xf8(%rsp),%rcx
    3f74:	00 
    3f75:	44 29 d0             	sub    %r10d,%eax
    3f78:	89 44 24 6c          	mov    %eax,0x6c(%rsp)
    3f7c:	42 0f b6 04 09       	movzbl (%rcx,%r9,1),%eax
    3f81:	48 8b 8c 24 f0 00 00 	mov    0xf0(%rsp),%rcx
    3f88:	00 
    3f89:	48 03 8c 24 00 01 00 	add    0x100(%rsp),%rcx
    3f90:	00 
    3f91:	48 03 84 24 28 01 00 	add    0x128(%rsp),%rax
    3f98:	00 
    3f99:	42 0f b6 74 09 ff    	movzbl -0x1(%rcx,%r9,1),%esi
    3f9f:	48 89 c2             	mov    %rax,%rdx
    3fa2:	48 29 f2             	sub    %rsi,%rdx
    3fa5:	0f b6 32             	movzbl (%rdx),%esi
    3fa8:	48 89 c2             	mov    %rax,%rdx
    3fab:	89 34 24             	mov    %esi,(%rsp)
    3fae:	42 0f b6 74 09 01    	movzbl 0x1(%rcx,%r9,1),%esi
    3fb4:	48 29 f2             	sub    %rsi,%rdx
    3fb7:	41 0f b6 34 24       	movzbl (%r12),%esi
    3fbc:	0f b6 3a             	movzbl (%rdx),%edi
    3fbf:	48 89 c2             	mov    %rax,%rdx
    3fc2:	48 29 f2             	sub    %rsi,%rdx
    3fc5:	41 0f b6 74 24 01    	movzbl 0x1(%r12),%esi
    3fcb:	0f b6 12             	movzbl (%rdx),%edx
    3fce:	89 bc 24 94 00 00 00 	mov    %edi,0x94(%rsp)
    3fd5:	41 89 fb             	mov    %edi,%r11d
    3fd8:	89 54 24 74          	mov    %edx,0x74(%rsp)
    3fdc:	48 89 c2             	mov    %rax,%rdx
    3fdf:	48 29 f2             	sub    %rsi,%rdx
    3fe2:	41 0f b6 74 24 02    	movzbl 0x2(%r12),%esi
    3fe8:	0f b6 12             	movzbl (%rdx),%edx
    3feb:	89 54 24 38          	mov    %edx,0x38(%rsp)
    3fef:	01 d2                	add    %edx,%edx
    3ff1:	89 94 24 c4 00 00 00 	mov    %edx,0xc4(%rsp)
    3ff8:	48 89 c2             	mov    %rax,%rdx
    3ffb:	48 29 f2             	sub    %rsi,%rdx
    3ffe:	41 0f b6 74 24 03    	movzbl 0x3(%r12),%esi
    4004:	0f b6 12             	movzbl (%rdx),%edx
    4007:	89 54 24 78          	mov    %edx,0x78(%rsp)
    400b:	48 89 c2             	mov    %rax,%rdx
    400e:	48 29 f2             	sub    %rsi,%rdx
    4011:	41 0f b6 74 24 04    	movzbl 0x4(%r12),%esi
    4017:	0f b6 12             	movzbl (%rdx),%edx
    401a:	89 54 24 40          	mov    %edx,0x40(%rsp)
    401e:	01 d2                	add    %edx,%edx
    4020:	89 94 24 c8 00 00 00 	mov    %edx,0xc8(%rsp)
    4027:	48 89 c2             	mov    %rax,%rdx
    402a:	48 29 f2             	sub    %rsi,%rdx
    402d:	0f b6 12             	movzbl (%rdx),%edx
    4030:	89 54 24 7c          	mov    %edx,0x7c(%rsp)
    4034:	48 8b 94 24 20 01 00 	mov    0x120(%rsp),%rdx
    403b:	00 
    403c:	42 0f b6 74 0a fd    	movzbl -0x3(%rdx,%r9,1),%esi
    4042:	48 89 c2             	mov    %rax,%rdx
    4045:	48 29 f2             	sub    %rsi,%rdx
    4048:	0f b6 12             	movzbl (%rdx),%edx
    404b:	41 0f b6 36          	movzbl (%r14),%esi
    404f:	89 54 24 0c          	mov    %edx,0xc(%rsp)
    4053:	48 89 c2             	mov    %rax,%rdx
    4056:	48 29 f2             	sub    %rsi,%rdx
    4059:	41 0f b6 76 01       	movzbl 0x1(%r14),%esi
    405e:	0f b6 12             	movzbl (%rdx),%edx
    4061:	89 54 24 4c          	mov    %edx,0x4c(%rsp)
    4065:	01 d2                	add    %edx,%edx
    4067:	89 94 24 cc 00 00 00 	mov    %edx,0xcc(%rsp)
    406e:	48 89 c2             	mov    %rax,%rdx
    4071:	48 29 f2             	sub    %rsi,%rdx
    4074:	41 0f b6 76 02       	movzbl 0x2(%r14),%esi
    4079:	0f b6 12             	movzbl (%rdx),%edx
    407c:	89 54 24 10          	mov    %edx,0x10(%rsp)
    4080:	48 89 c2             	mov    %rax,%rdx
    4083:	48 29 f2             	sub    %rsi,%rdx
    4086:	41 0f b6 76 03       	movzbl 0x3(%r14),%esi
    408b:	0f b6 12             	movzbl (%rdx),%edx
    408e:	89 94 24 80 00 00 00 	mov    %edx,0x80(%rsp)
    4095:	48 89 c2             	mov    %rax,%rdx
    4098:	48 29 f2             	sub    %rsi,%rdx
    409b:	41 0f b6 76 04       	movzbl 0x4(%r14),%esi
    40a0:	0f b6 12             	movzbl (%rdx),%edx
    40a3:	89 54 24 48          	mov    %edx,0x48(%rsp)
    40a7:	48 89 c2             	mov    %rax,%rdx
    40aa:	48 29 f2             	sub    %rsi,%rdx
    40ad:	41 0f b6 76 05       	movzbl 0x5(%r14),%esi
    40b2:	0f b6 12             	movzbl (%rdx),%edx
    40b5:	89 54 24 50          	mov    %edx,0x50(%rsp)
    40b9:	01 d2                	add    %edx,%edx
    40bb:	89 94 24 d0 00 00 00 	mov    %edx,0xd0(%rsp)
    40c2:	48 89 c2             	mov    %rax,%rdx
    40c5:	48 29 f2             	sub    %rsi,%rdx
    40c8:	43 0f b6 74 0d fd    	movzbl -0x3(%r13,%r9,1),%esi
    40ce:	0f b6 12             	movzbl (%rdx),%edx
    40d1:	89 54 24 18          	mov    %edx,0x18(%rsp)
    40d5:	48 89 c2             	mov    %rax,%rdx
    40d8:	48 29 f2             	sub    %rsi,%rdx
    40db:	43 0f b6 74 0d fe    	movzbl -0x2(%r13,%r9,1),%esi
    40e1:	0f b6 12             	movzbl (%rdx),%edx
    40e4:	89 94 24 98 00 00 00 	mov    %edx,0x98(%rsp)
    40eb:	48 89 c2             	mov    %rax,%rdx
    40ee:	48 29 f2             	sub    %rsi,%rdx
    40f1:	43 0f b6 74 0d ff    	movzbl -0x1(%r13,%r9,1),%esi
    40f7:	0f b6 12             	movzbl (%rdx),%edx
    40fa:	89 94 24 9c 00 00 00 	mov    %edx,0x9c(%rsp)
    4101:	48 89 c2             	mov    %rax,%rdx
    4104:	48 29 f2             	sub    %rsi,%rdx
    4107:	43 0f b6 74 0d 01    	movzbl 0x1(%r13,%r9,1),%esi
    410d:	0f b6 12             	movzbl (%rdx),%edx
    4110:	89 94 24 a0 00 00 00 	mov    %edx,0xa0(%rsp)
    4117:	48 89 c2             	mov    %rax,%rdx
    411a:	48 29 f2             	sub    %rsi,%rdx
    411d:	0f b6 12             	movzbl (%rdx),%edx
    4120:	43 0f b6 74 0d 02    	movzbl 0x2(%r13,%r9,1),%esi
    4126:	89 94 24 a4 00 00 00 	mov    %edx,0xa4(%rsp)
    412d:	48 89 c2             	mov    %rax,%rdx
    4130:	48 29 f2             	sub    %rsi,%rdx
    4133:	43 0f b6 74 0d 03    	movzbl 0x3(%r13,%r9,1),%esi
    4139:	0f b6 12             	movzbl (%rdx),%edx
    413c:	89 94 24 a8 00 00 00 	mov    %edx,0xa8(%rsp)
    4143:	48 89 c2             	mov    %rax,%rdx
    4146:	48 29 f2             	sub    %rsi,%rdx
    4149:	0f b6 1a             	movzbl (%rdx),%ebx
    414c:	48 8b 94 24 18 01 00 	mov    0x118(%rsp),%rdx
    4153:	00 
    4154:	42 0f b6 74 0a fd    	movzbl -0x3(%rdx,%r9,1),%esi
    415a:	48 89 c2             	mov    %rax,%rdx
    415d:	89 9c 24 ac 00 00 00 	mov    %ebx,0xac(%rsp)
    4164:	48 29 f2             	sub    %rsi,%rdx
    4167:	41 0f b6 37          	movzbl (%r15),%esi
    416b:	0f b6 3a             	movzbl (%rdx),%edi
    416e:	8d 14 bd 00 00 00 00 	lea    0x0(,%rdi,4),%edx
    4175:	89 7c 24 54          	mov    %edi,0x54(%rsp)
    4179:	29 d7                	sub    %edx,%edi
    417b:	48 89 c2             	mov    %rax,%rdx
    417e:	48 29 f2             	sub    %rsi,%rdx
    4181:	41 0f b6 77 01       	movzbl 0x1(%r15),%esi
    4186:	89 bc 24 e4 00 00 00 	mov    %edi,0xe4(%rsp)
    418d:	0f b6 12             	movzbl (%rdx),%edx
    4190:	8d 1c 12             	lea    (%rdx,%rdx,1),%ebx
    4193:	89 54 24 58          	mov    %edx,0x58(%rsp)
    4197:	48 89 c2             	mov    %rax,%rdx
    419a:	48 29 f2             	sub    %rsi,%rdx
    419d:	41 0f b6 77 02       	movzbl 0x2(%r15),%esi
    41a2:	89 9c 24 d4 00 00 00 	mov    %ebx,0xd4(%rsp)
    41a9:	0f b6 12             	movzbl (%rdx),%edx
    41ac:	89 54 24 20          	mov    %edx,0x20(%rsp)
    41b0:	48 89 c2             	mov    %rax,%rdx
    41b3:	48 29 f2             	sub    %rsi,%rdx
    41b6:	41 0f b6 77 03       	movzbl 0x3(%r15),%esi
    41bb:	0f b6 1a             	movzbl (%rdx),%ebx
    41be:	48 89 c2             	mov    %rax,%rdx
    41c1:	48 29 f2             	sub    %rsi,%rdx
    41c4:	41 0f b6 77 04       	movzbl 0x4(%r15),%esi
    41c9:	0f b6 12             	movzbl (%rdx),%edx
    41cc:	89 9c 24 84 00 00 00 	mov    %ebx,0x84(%rsp)
    41d3:	89 54 24 28          	mov    %edx,0x28(%rsp)
    41d7:	48 89 c2             	mov    %rax,%rdx
    41da:	48 29 f2             	sub    %rsi,%rdx
    41dd:	41 0f b6 77 05       	movzbl 0x5(%r15),%esi
    41e2:	0f b6 12             	movzbl (%rdx),%edx
    41e5:	8d 1c 12             	lea    (%rdx,%rdx,1),%ebx
    41e8:	89 54 24 5c          	mov    %edx,0x5c(%rsp)
    41ec:	48 89 c2             	mov    %rax,%rdx
    41ef:	48 29 f2             	sub    %rsi,%rdx
    41f2:	89 9c 24 d8 00 00 00 	mov    %ebx,0xd8(%rsp)
    41f9:	0f b6 1a             	movzbl (%rdx),%ebx
    41fc:	8d 14 5b             	lea    (%rbx,%rbx,2),%edx
    41ff:	89 94 24 e8 00 00 00 	mov    %edx,0xe8(%rsp)
    4206:	48 89 c2             	mov    %rax,%rdx
    4209:	48 8b bc 24 10 01 00 	mov    0x110(%rsp),%rdi
    4210:	00 
    4211:	4c 8b 84 24 08 01 00 	mov    0x108(%rsp),%r8
    4218:	00 
    4219:	42 0f b6 0c 09       	movzbl (%rcx,%r9,1),%ecx
    421e:	42 0f b6 74 0f fe    	movzbl -0x2(%rdi,%r9,1),%esi
    4224:	48 29 f2             	sub    %rsi,%rdx
    4227:	42 0f b6 74 0f ff    	movzbl -0x1(%rdi,%r9,1),%esi
    422d:	0f b6 12             	movzbl (%rdx),%edx
    4230:	89 94 24 88 00 00 00 	mov    %edx,0x88(%rsp)
    4237:	48 89 c2             	mov    %rax,%rdx
    423a:	48 29 f2             	sub    %rsi,%rdx
    423d:	42 0f b6 34 0f       	movzbl (%rdi,%r9,1),%esi
    4242:	0f b6 12             	movzbl (%rdx),%edx
    4245:	89 54 24 60          	mov    %edx,0x60(%rsp)
    4249:	01 d2                	add    %edx,%edx
    424b:	89 94 24 dc 00 00 00 	mov    %edx,0xdc(%rsp)
    4252:	48 89 c2             	mov    %rax,%rdx
    4255:	48 29 f2             	sub    %rsi,%rdx
    4258:	0f b6 32             	movzbl (%rdx),%esi
    425b:	48 89 c2             	mov    %rax,%rdx
    425e:	89 b4 24 8c 00 00 00 	mov    %esi,0x8c(%rsp)
    4265:	42 0f b6 74 0f 01    	movzbl 0x1(%rdi,%r9,1),%esi
    426b:	42 0f b6 7c 0f 02    	movzbl 0x2(%rdi,%r9,1),%edi
    4271:	48 29 f2             	sub    %rsi,%rdx
    4274:	0f b6 32             	movzbl (%rdx),%esi
    4277:	8d 14 36             	lea    (%rsi,%rsi,1),%edx
    427a:	89 94 24 e0 00 00 00 	mov    %edx,0xe0(%rsp)
    4281:	48 89 c2             	mov    %rax,%rdx
    4284:	48 29 fa             	sub    %rdi,%rdx
    4287:	43 0f b6 7c 08 ff    	movzbl -0x1(%r8,%r9,1),%edi
    428d:	0f b6 12             	movzbl (%rdx),%edx
    4290:	89 94 24 90 00 00 00 	mov    %edx,0x90(%rsp)
    4297:	48 89 c2             	mov    %rax,%rdx
    429a:	48 29 fa             	sub    %rdi,%rdx
    429d:	43 0f b6 3c 08       	movzbl (%r8,%r9,1),%edi
    42a2:	47 0f b6 44 08 01    	movzbl 0x1(%r8,%r9,1),%r8d
    42a8:	0f b6 12             	movzbl (%rdx),%edx
    42ab:	89 54 24 30          	mov    %edx,0x30(%rsp)
    42af:	48 89 c2             	mov    %rax,%rdx
    42b2:	48 29 fa             	sub    %rdi,%rdx
    42b5:	48 89 c7             	mov    %rax,%rdi
    42b8:	48 29 c8             	sub    %rcx,%rax
    42bb:	4c 29 c7             	sub    %r8,%rdi
    42be:	0f b6 08             	movzbl (%rax),%ecx
    42c1:	03 0c 24             	add    (%rsp),%ecx
    42c4:	0f b6 2f             	movzbl (%rdi),%ebp
    42c7:	44 01 d9             	add    %r11d,%ecx
    42ca:	81 7c 24 6c 58 02 00 	cmpl   $0x258,0x6c(%rsp)
    42d1:	00 
    42d2:	0f b6 12             	movzbl (%rdx),%edx
    42d5:	44 8d 44 6d 00       	lea    0x0(%rbp,%rbp,2),%r8d
    42da:	44 89 84 24 ec 00 00 	mov    %r8d,0xec(%rsp)
    42e1:	00 
    42e2:	0f 8f c0 01 00 00    	jg     44a8 <susan_edges+0xc48>
    42e8:	8d 04 c9             	lea    (%rcx,%rcx,8),%eax
    42eb:	8b 4c 24 74          	mov    0x74(%rsp),%ecx
    42ef:	8b 7c 24 38          	mov    0x38(%rsp),%edi
    42f3:	8d 14 d2             	lea    (%rdx,%rdx,8),%edx
    42f6:	44 8b 84 24 88 00 00 	mov    0x88(%rsp),%r8d
    42fd:	00 
    42fe:	44 8b 5c 24 60       	mov    0x60(%rsp),%r11d
    4303:	c1 e1 02             	shl    $0x2,%ecx
    4306:	01 c8                	add    %ecx,%eax
    4308:	41 c1 e0 02          	shl    $0x2,%r8d
    430c:	8d 04 b8             	lea    (%rax,%rdi,4),%eax
    430f:	8b 7c 24 78          	mov    0x78(%rsp),%edi
    4313:	8d 04 b8             	lea    (%rax,%rdi,4),%eax
    4316:	8b 7c 24 40          	mov    0x40(%rsp),%edi
    431a:	8d 04 b8             	lea    (%rax,%rdi,4),%eax
    431d:	8b 7c 24 7c          	mov    0x7c(%rsp),%edi
    4321:	c1 e7 02             	shl    $0x2,%edi
    4324:	01 f8                	add    %edi,%eax
    4326:	03 44 24 0c          	add    0xc(%rsp),%eax
    432a:	03 44 24 4c          	add    0x4c(%rsp),%eax
    432e:	03 44 24 10          	add    0x10(%rsp),%eax
    4332:	03 84 24 80 00 00 00 	add    0x80(%rsp),%eax
    4339:	03 44 24 48          	add    0x48(%rsp),%eax
    433d:	03 44 24 50          	add    0x50(%rsp),%eax
    4341:	03 44 24 18          	add    0x18(%rsp),%eax
    4345:	03 44 24 54          	add    0x54(%rsp),%eax
    4349:	03 44 24 58          	add    0x58(%rsp),%eax
    434d:	03 44 24 20          	add    0x20(%rsp),%eax
    4351:	03 84 24 84 00 00 00 	add    0x84(%rsp),%eax
    4358:	03 44 24 28          	add    0x28(%rsp),%eax
    435c:	03 44 24 5c          	add    0x5c(%rsp),%eax
    4360:	01 d8                	add    %ebx,%eax
    4362:	44 01 c0             	add    %r8d,%eax
    4365:	42 8d 04 98          	lea    (%rax,%r11,4),%eax
    4369:	44 8b 9c 24 8c 00 00 	mov    0x8c(%rsp),%r11d
    4370:	00 
    4371:	42 8d 04 98          	lea    (%rax,%r11,4),%eax
    4375:	44 8b 9c 24 90 00 00 	mov    0x90(%rsp),%r11d
    437c:	00 
    437d:	8d 04 b0             	lea    (%rax,%rsi,4),%eax
    4380:	41 c1 e3 02          	shl    $0x2,%r11d
    4384:	44 01 d8             	add    %r11d,%eax
    4387:	44 89 5c 24 6c       	mov    %r11d,0x6c(%rsp)
    438c:	44 8b 5c 24 30       	mov    0x30(%rsp),%r11d
    4391:	47 8d 1c db          	lea    (%r11,%r11,8),%r11d
    4395:	44 01 d8             	add    %r11d,%eax
    4398:	01 d0                	add    %edx,%eax
    439a:	8d 54 ed 00          	lea    0x0(%rbp,%rbp,8),%edx
    439e:	01 c2                	add    %eax,%edx
    43a0:	0f 84 fa fa ff ff    	je     3ea0 <susan_edges+0x640>
    43a6:	8b 04 24             	mov    (%rsp),%eax
    43a9:	44 8b 5c 24 0c       	mov    0xc(%rsp),%r11d
    43ae:	66 0f ef c0          	pxor   %xmm0,%xmm0
    43b2:	66 0f ef c9          	pxor   %xmm1,%xmm1
    43b6:	03 84 24 94 00 00 00 	add    0x94(%rsp),%eax
    43bd:	f3 0f 2a ca          	cvtsi2ss %edx,%xmm1
    43c1:	01 c8                	add    %ecx,%eax
    43c3:	03 44 24 38          	add    0x38(%rsp),%eax
    43c7:	47 8d 1c db          	lea    (%r11,%r11,8),%r11d
    43cb:	03 44 24 40          	add    0x40(%rsp),%eax
    43cf:	01 f8                	add    %edi,%eax
    43d1:	41 01 c3             	add    %eax,%r11d
    43d4:	8b 44 24 4c          	mov    0x4c(%rsp),%eax
    43d8:	41 8d 04 83          	lea    (%r11,%rax,4),%eax
    43dc:	44 8b 5c 24 50       	mov    0x50(%rsp),%r11d
    43e1:	03 44 24 10          	add    0x10(%rsp),%eax
    43e5:	03 44 24 48          	add    0x48(%rsp),%eax
    43e9:	46 8d 1c 98          	lea    (%rax,%r11,4),%r11d
    43ed:	8b 44 24 18          	mov    0x18(%rsp),%eax
    43f1:	8d 04 c0             	lea    (%rax,%rax,8),%eax
    43f4:	41 01 c3             	add    %eax,%r11d
    43f7:	8b 84 24 98 00 00 00 	mov    0x98(%rsp),%eax
    43fe:	8d 04 c0             	lea    (%rax,%rax,8),%eax
    4401:	44 01 d8             	add    %r11d,%eax
    4404:	44 8b 9c 24 9c 00 00 	mov    0x9c(%rsp),%r11d
    440b:	00 
    440c:	42 8d 04 98          	lea    (%rax,%r11,4),%eax
    4410:	44 8b 9c 24 a8 00 00 	mov    0xa8(%rsp),%r11d
    4417:	00 
    4418:	03 84 24 a0 00 00 00 	add    0xa0(%rsp),%eax
    441f:	03 84 24 a4 00 00 00 	add    0xa4(%rsp),%eax
    4426:	46 8d 1c 98          	lea    (%rax,%r11,4),%r11d
    442a:	8b 84 24 ac 00 00 00 	mov    0xac(%rsp),%eax
    4431:	8d 04 c0             	lea    (%rax,%rax,8),%eax
    4434:	44 01 d8             	add    %r11d,%eax
    4437:	44 8b 5c 24 54       	mov    0x54(%rsp),%r11d
    443c:	47 8d 1c db          	lea    (%r11,%r11,8),%r11d
    4440:	41 01 c3             	add    %eax,%r11d
    4443:	8b 44 24 58          	mov    0x58(%rsp),%eax
    4447:	41 8d 04 83          	lea    (%r11,%rax,4),%eax
    444b:	44 8b 5c 24 5c       	mov    0x5c(%rsp),%r11d
    4450:	03 44 24 20          	add    0x20(%rsp),%eax
    4454:	03 44 24 28          	add    0x28(%rsp),%eax
    4458:	42 8d 04 98          	lea    (%rax,%r11,4),%eax
    445c:	44 8d 1c db          	lea    (%rbx,%rbx,8),%r11d
    4460:	41 01 c3             	add    %eax,%r11d
    4463:	45 01 c3             	add    %r8d,%r11d
    4466:	44 03 5c 24 60       	add    0x60(%rsp),%r11d
    446b:	41 01 f3             	add    %esi,%r11d
    446e:	44 03 5c 24 6c       	add    0x6c(%rsp),%r11d
    4473:	44 03 5c 24 30       	add    0x30(%rsp),%r11d
    4478:	41 01 eb             	add    %ebp,%r11d
    447b:	f3 41 0f 2a c3       	cvtsi2ss %r11d,%xmm0
    4480:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    4484:	0f 2f d0             	comiss %xmm0,%xmm2
    4487:	0f 86 b3 02 00 00    	jbe    4740 <susan_edges+0xee0>
    448d:	8b 44 24 64          	mov    0x64(%rsp),%eax
    4491:	be 02 00 00 00       	mov    $0x2,%esi
    4496:	31 ff                	xor    %edi,%edi
    4498:	ba 01 00 00 00       	mov    $0x1,%edx
    449d:	31 c9                	xor    %ecx,%ecx
    449f:	e9 0c fa ff ff       	jmp    3eb0 <susan_edges+0x650>
    44a4:	0f 1f 40 00          	nopl   0x0(%rax)
    44a8:	8d 3c 8d 00 00 00 00 	lea    0x0(,%rcx,4),%edi
    44af:	89 c8                	mov    %ecx,%eax
    44b1:	66 0f ef c0          	pxor   %xmm0,%xmm0
    44b5:	45 89 d8             	mov    %r11d,%r8d
    44b8:	29 f8                	sub    %edi,%eax
    44ba:	8b 7c 24 74          	mov    0x74(%rsp),%edi
    44be:	44 2b 04 24          	sub    (%rsp),%r8d
    44c2:	44 8b 5c 24 0c       	mov    0xc(%rsp),%r11d
    44c7:	01 ff                	add    %edi,%edi
    44c9:	41 29 f8             	sub    %edi,%r8d
    44cc:	29 f8                	sub    %edi,%eax
    44ce:	8b 7c 24 78          	mov    0x78(%rsp),%edi
    44d2:	2b 84 24 c4 00 00 00 	sub    0xc4(%rsp),%eax
    44d9:	44 2b 44 24 38       	sub    0x38(%rsp),%r8d
    44de:	44 03 44 24 40       	add    0x40(%rsp),%r8d
    44e3:	01 ff                	add    %edi,%edi
    44e5:	29 f8                	sub    %edi,%eax
    44e7:	8b 7c 24 7c          	mov    0x7c(%rsp),%edi
    44eb:	2b 84 24 c8 00 00 00 	sub    0xc8(%rsp),%eax
    44f2:	01 ff                	add    %edi,%edi
    44f4:	29 f8                	sub    %edi,%eax
    44f6:	41 01 f8             	add    %edi,%r8d
    44f9:	42 8d 3c 9d 00 00 00 	lea    0x0(,%r11,4),%edi
    4500:	00 
    4501:	89 84 24 44 01 00 00 	mov    %eax,0x144(%rsp)
    4508:	44 89 d8             	mov    %r11d,%eax
    450b:	29 f8                	sub    %edi,%eax
    450d:	42 8d 3c 00          	lea    (%rax,%r8,1),%edi
    4511:	8b 84 24 44 01 00 00 	mov    0x144(%rsp),%eax
    4518:	44 8b 44 24 10       	mov    0x10(%rsp),%r8d
    451d:	2b bc 24 cc 00 00 00 	sub    0xcc(%rsp),%edi
    4524:	44 29 d8             	sub    %r11d,%eax
    4527:	2b 44 24 4c          	sub    0x4c(%rsp),%eax
    452b:	44 29 c7             	sub    %r8d,%edi
    452e:	44 8b 5c 24 18       	mov    0x18(%rsp),%r11d
    4533:	44 29 c0             	sub    %r8d,%eax
    4536:	44 8b 44 24 48       	mov    0x48(%rsp),%r8d
    453b:	2b 84 24 80 00 00 00 	sub    0x80(%rsp),%eax
    4542:	44 29 c0             	sub    %r8d,%eax
    4545:	2b 44 24 50          	sub    0x50(%rsp),%eax
    4549:	44 01 c7             	add    %r8d,%edi
    454c:	03 bc 24 d0 00 00 00 	add    0xd0(%rsp),%edi
    4553:	44 29 d8             	sub    %r11d,%eax
    4556:	47 8d 04 5b          	lea    (%r11,%r11,2),%r8d
    455a:	44 8b 9c 24 98 00 00 	mov    0x98(%rsp),%r11d
    4561:	00 
    4562:	41 01 f8             	add    %edi,%r8d
    4565:	42 8d 3c 9d 00 00 00 	lea    0x0(,%r11,4),%edi
    456c:	00 
    456d:	41 29 fb             	sub    %edi,%r11d
    4570:	43 8d 3c 03          	lea    (%r11,%r8,1),%edi
    4574:	44 8b 84 24 9c 00 00 	mov    0x9c(%rsp),%r8d
    457b:	00 
    457c:	45 01 c0             	add    %r8d,%r8d
    457f:	44 29 c7             	sub    %r8d,%edi
    4582:	44 8b 84 24 a8 00 00 	mov    0xa8(%rsp),%r8d
    4589:	00 
    458a:	2b bc 24 a0 00 00 00 	sub    0xa0(%rsp),%edi
    4591:	03 bc 24 a4 00 00 00 	add    0xa4(%rsp),%edi
    4598:	46 8d 04 47          	lea    (%rdi,%r8,2),%r8d
    459c:	8b bc 24 ac 00 00 00 	mov    0xac(%rsp),%edi
    45a3:	8d 3c 7f             	lea    (%rdi,%rdi,2),%edi
    45a6:	44 01 c7             	add    %r8d,%edi
    45a9:	44 8b 44 24 20       	mov    0x20(%rsp),%r8d
    45ae:	03 44 24 54          	add    0x54(%rsp),%eax
    45b2:	03 bc 24 e4 00 00 00 	add    0xe4(%rsp),%edi
    45b9:	03 44 24 58          	add    0x58(%rsp),%eax
    45bd:	2b bc 24 d4 00 00 00 	sub    0xd4(%rsp),%edi
    45c4:	44 01 c0             	add    %r8d,%eax
    45c7:	03 84 24 84 00 00 00 	add    0x84(%rsp),%eax
    45ce:	44 29 c7             	sub    %r8d,%edi
    45d1:	44 8b 44 24 28       	mov    0x28(%rsp),%r8d
    45d6:	44 01 c7             	add    %r8d,%edi
    45d9:	44 01 c0             	add    %r8d,%eax
    45dc:	03 bc 24 d8 00 00 00 	add    0xd8(%rsp),%edi
    45e3:	44 8b 84 24 88 00 00 	mov    0x88(%rsp),%r8d
    45ea:	00 
    45eb:	03 44 24 5c          	add    0x5c(%rsp),%eax
    45ef:	03 bc 24 e8 00 00 00 	add    0xe8(%rsp),%edi
    45f6:	01 d8                	add    %ebx,%eax
    45f8:	45 01 c0             	add    %r8d,%r8d
    45fb:	44 29 c7             	sub    %r8d,%edi
    45fe:	41 01 c0             	add    %eax,%r8d
    4601:	8b 84 24 8c 00 00 00 	mov    0x8c(%rsp),%eax
    4608:	2b 7c 24 60          	sub    0x60(%rsp),%edi
    460c:	44 03 84 24 dc 00 00 	add    0xdc(%rsp),%r8d
    4613:	00 
    4614:	45 8d 04 40          	lea    (%r8,%rax,2),%r8d
    4618:	8d 04 37             	lea    (%rdi,%rsi,1),%eax
    461b:	8b bc 24 e0 00 00 00 	mov    0xe0(%rsp),%edi
    4622:	44 01 c7             	add    %r8d,%edi
    4625:	44 8b 84 24 90 00 00 	mov    0x90(%rsp),%r8d
    462c:	00 
    462d:	45 01 c0             	add    %r8d,%r8d
    4630:	44 01 c0             	add    %r8d,%eax
    4633:	41 01 f8             	add    %edi,%r8d
    4636:	8b 7c 24 30          	mov    0x30(%rsp),%edi
    463a:	29 f8                	sub    %edi,%eax
    463c:	8d 3c 7f             	lea    (%rdi,%rdi,2),%edi
    463f:	44 01 c7             	add    %r8d,%edi
    4642:	44 8d 04 52          	lea    (%rdx,%rdx,2),%r8d
    4646:	01 e8                	add    %ebp,%eax
    4648:	44 01 c7             	add    %r8d,%edi
    464b:	03 bc 24 ec 00 00 00 	add    0xec(%rsp),%edi
    4652:	41 89 c0             	mov    %eax,%r8d
    4655:	41 89 fb             	mov    %edi,%r11d
    4658:	44 0f af c0          	imul   %eax,%r8d
    465c:	44 0f af df          	imul   %edi,%r11d
    4660:	45 01 d8             	add    %r11d,%r8d
    4663:	f3 41 0f 2a c0       	cvtsi2ss %r8d,%xmm0
    4668:	0f 2e e0             	ucomiss %xmm0,%xmm4
    466b:	0f 87 e4 02 00 00    	ja     4955 <susan_edges+0x10f5>
    4671:	f3 0f 51 c0          	sqrtss %xmm0,%xmm0
    4675:	66 0f ef c9          	pxor   %xmm1,%xmm1
    4679:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    467d:	f3 0f 2a 4c 24 6c    	cvtsi2ssl 0x6c(%rsp),%xmm1
    4683:	f3 0f 5a c9          	cvtss2sd %xmm1,%xmm1
    4687:	f2 0f 59 cb          	mulsd  %xmm3,%xmm1
    468b:	66 0f 2f c1          	comisd %xmm1,%xmm0
    468f:	0f 86 53 fc ff ff    	jbe    42e8 <susan_edges+0xa88>
    4695:	85 c0                	test   %eax,%eax
    4697:	0f 85 2b 02 00 00    	jne    48c8 <susan_edges+0x1068>
    469d:	8b 4c 24 68          	mov    0x68(%rsp),%ecx
    46a1:	be 02 00 00 00       	mov    $0x2,%esi
    46a6:	8d 14 01             	lea    (%rcx,%rax,1),%edx
    46a9:	b9 01 00 00 00       	mov    $0x1,%ecx
    46ae:	48 8b bc 24 30 01 00 	mov    0x130(%rsp),%rdi
    46b5:	00 
    46b6:	48 63 d2             	movslq %edx,%rdx
    46b9:	44 3b 14 97          	cmp    (%rdi,%rdx,4),%r10d
    46bd:	0f 8e 5d f8 ff ff    	jle    3f20 <susan_edges+0x6c0>
    46c3:	8b 9c 24 40 01 00 00 	mov    0x140(%rsp),%ebx
    46ca:	44 8b 84 24 3c 01 00 	mov    0x13c(%rsp),%r8d
    46d1:	00 
    46d2:	44 8b 5c 24 70       	mov    0x70(%rsp),%r11d
    46d7:	89 da                	mov    %ebx,%edx
    46d9:	29 ca                	sub    %ecx,%edx
    46db:	48 89 f9             	mov    %rdi,%rcx
    46de:	41 0f af d0          	imul   %r8d,%edx
    46e2:	44 01 da             	add    %r11d,%edx
    46e5:	29 c2                	sub    %eax,%edx
    46e7:	48 63 d2             	movslq %edx,%rdx
    46ea:	44 3b 14 97          	cmp    (%rdi,%rdx,4),%r10d
    46ee:	0f 8c 2c f8 ff ff    	jl     3f20 <susan_edges+0x6c0>
    46f4:	8d 14 33             	lea    (%rbx,%rsi,1),%edx
    46f7:	01 c0                	add    %eax,%eax
    46f9:	89 df                	mov    %ebx,%edi
    46fb:	41 0f af d0          	imul   %r8d,%edx
    46ff:	44 01 da             	add    %r11d,%edx
    4702:	01 c2                	add    %eax,%edx
    4704:	48 63 d2             	movslq %edx,%rdx
    4707:	44 3b 14 91          	cmp    (%rcx,%rdx,4),%r10d
    470b:	0f 8e 0f f8 ff ff    	jle    3f20 <susan_edges+0x6c0>
    4711:	29 f7                	sub    %esi,%edi
    4713:	89 fa                	mov    %edi,%edx
    4715:	41 0f af d0          	imul   %r8d,%edx
    4719:	44 01 da             	add    %r11d,%edx
    471c:	29 c2                	sub    %eax,%edx
    471e:	48 63 d2             	movslq %edx,%rdx
    4721:	44 3b 14 91          	cmp    (%rcx,%rdx,4),%r10d
    4725:	0f 8c f5 f7 ff ff    	jl     3f20 <susan_edges+0x6c0>
    472b:	48 8b 84 24 60 01 00 	mov    0x160(%rsp),%rax
    4732:	00 
    4733:	42 c6 04 08 01       	movb   $0x1,(%rax,%r9,1)
    4738:	e9 e3 f7 ff ff       	jmp    3f20 <susan_edges+0x6c0>
    473d:	0f 1f 00             	nopl   (%rax)
    4740:	0f 2f 05 79 2f 00 00 	comiss 0x2f79(%rip),%xmm0        # 76c0 <_IO_stdin_used+0x6c0>
    4747:	0f 87 a1 02 00 00    	ja     49ee <susan_edges+0x118e>
    474d:	8b 04 24             	mov    (%rsp),%eax
    4750:	8d 14 40             	lea    (%rax,%rax,2),%edx
    4753:	8b 84 24 94 00 00 00 	mov    0x94(%rsp),%eax
    475a:	8d 34 85 00 00 00 00 	lea    0x0(,%rax,4),%esi
    4761:	29 f0                	sub    %esi,%eax
    4763:	8b 74 24 30          	mov    0x30(%rsp),%esi
    4767:	01 c2                	add    %eax,%edx
    4769:	8b 44 24 0c          	mov    0xc(%rsp),%eax
    476d:	01 d1                	add    %edx,%ecx
    476f:	03 8c 24 c4 00 00 00 	add    0xc4(%rsp),%ecx
    4776:	2b 8c 24 c8 00 00 00 	sub    0xc8(%rsp),%ecx
    477d:	29 f9                	sub    %edi,%ecx
    477f:	8d 04 40             	lea    (%rax,%rax,2),%eax
    4782:	01 c8                	add    %ecx,%eax
    4784:	8b 4c 24 18          	mov    0x18(%rsp),%ecx
    4788:	03 84 24 cc 00 00 00 	add    0xcc(%rsp),%eax
    478f:	03 44 24 10          	add    0x10(%rsp),%eax
    4793:	2b 44 24 48          	sub    0x48(%rsp),%eax
    4797:	8d 14 8d 00 00 00 00 	lea    0x0(,%rcx,4),%edx
    479e:	2b 84 24 d0 00 00 00 	sub    0xd0(%rsp),%eax
    47a5:	29 d1                	sub    %edx,%ecx
    47a7:	01 c1                	add    %eax,%ecx
    47a9:	8d 04 b5 00 00 00 00 	lea    0x0(,%rsi,4),%eax
    47b0:	03 8c 24 e4 00 00 00 	add    0xe4(%rsp),%ecx
    47b7:	2b 8c 24 d4 00 00 00 	sub    0xd4(%rsp),%ecx
    47be:	29 c6                	sub    %eax,%esi
    47c0:	2b 4c 24 20          	sub    0x20(%rsp),%ecx
    47c4:	03 4c 24 28          	add    0x28(%rsp),%ecx
    47c8:	03 8c 24 d8 00 00 00 	add    0xd8(%rsp),%ecx
    47cf:	03 8c 24 e8 00 00 00 	add    0xe8(%rsp),%ecx
    47d6:	89 f3                	mov    %esi,%ebx
    47d8:	44 29 c1             	sub    %r8d,%ecx
    47db:	2b 8c 24 dc 00 00 00 	sub    0xdc(%rsp),%ecx
    47e2:	03 8c 24 e0 00 00 00 	add    0xe0(%rsp),%ecx
    47e9:	03 4c 24 6c          	add    0x6c(%rsp),%ecx
    47ed:	01 cb                	add    %ecx,%ebx
    47ef:	03 9c 24 ec 00 00 00 	add    0xec(%rsp),%ebx
    47f6:	85 db                	test   %ebx,%ebx
    47f8:	0f 8e 9a 00 00 00    	jle    4898 <susan_edges+0x1038>
    47fe:	be 02 00 00 00       	mov    $0x2,%esi
    4803:	bf fe ff ff ff       	mov    $0xfffffffe,%edi
    4808:	ba 01 00 00 00       	mov    $0x1,%edx
    480d:	8b 8c 24 c0 00 00 00 	mov    0xc0(%rsp),%ecx
    4814:	8b 84 24 68 01 00 00 	mov    0x168(%rsp),%eax
    481b:	8d 44 08 01          	lea    0x1(%rax,%rcx,1),%eax
    481f:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    4824:	e9 87 f6 ff ff       	jmp    3eb0 <susan_edges+0x650>
    4829:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    4830:	8b 8c 24 3c 01 00 00 	mov    0x13c(%rsp),%ecx
    4837:	48 8b b4 24 70 01 00 	mov    0x170(%rsp),%rsi
    483e:	00 
    483f:	01 8c 24 5c 01 00 00 	add    %ecx,0x15c(%rsp)
    4846:	01 8c 24 4c 01 00 00 	add    %ecx,0x14c(%rsp)
    484d:	48 8b 8c 24 50 01 00 	mov    0x150(%rsp),%rcx
    4854:	00 
    4855:	48 01 b4 24 60 01 00 	add    %rsi,0x160(%rsp)
    485c:	00 
    485d:	48 01 8c 24 b0 00 00 	add    %rcx,0xb0(%rsp)
    4864:	00 
    4865:	8b 8c 24 48 01 00 00 	mov    0x148(%rsp),%ecx
    486c:	48 01 b4 24 f8 00 00 	add    %rsi,0xf8(%rsp)
    4873:	00 
    4874:	39 8c 24 6c 01 00 00 	cmp    %ecx,0x16c(%rsp)
    487b:	0f 85 07 f5 ff ff    	jne    3d88 <susan_edges+0x528>
    4881:	48 81 c4 d8 01 00 00 	add    $0x1d8,%rsp
    4888:	5b                   	pop    %rbx
    4889:	5d                   	pop    %rbp
    488a:	41 5c                	pop    %r12
    488c:	41 5d                	pop    %r13
    488e:	41 5e                	pop    %r14
    4890:	41 5f                	pop    %r15
    4892:	c3                   	ret    
    4893:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    4898:	be 02 00 00 00       	mov    $0x2,%esi
    489d:	bf 02 00 00 00       	mov    $0x2,%edi
    48a2:	ba 01 00 00 00       	mov    $0x1,%edx
    48a7:	8b 8c 24 c0 00 00 00 	mov    0xc0(%rsp),%ecx
    48ae:	8b 84 24 4c 01 00 00 	mov    0x14c(%rsp),%eax
    48b5:	8d 44 08 01          	lea    0x1(%rax,%rcx,1),%eax
    48b9:	b9 01 00 00 00       	mov    $0x1,%ecx
    48be:	e9 ed f5 ff ff       	jmp    3eb0 <susan_edges+0x650>
    48c3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    48c8:	66 0f ef c0          	pxor   %xmm0,%xmm0
    48cc:	66 0f ef c9          	pxor   %xmm1,%xmm1
    48d0:	f3 0f 2a c7          	cvtsi2ss %edi,%xmm0
    48d4:	f3 0f 2a c8          	cvtsi2ss %eax,%xmm1
    48d8:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    48dc:	0f 2f e0             	comiss %xmm0,%xmm4
    48df:	76 2b                	jbe    490c <susan_edges+0x10ac>
    48e1:	0f 2f 05 cc 2d 00 00 	comiss 0x2dcc(%rip),%xmm0        # 76b4 <_IO_stdin_used+0x6b4>
    48e8:	77 33                	ja     491d <susan_edges+0x10bd>
    48ea:	f3 0f 10 0d c6 2d 00 	movss  0x2dc6(%rip),%xmm1        # 76b8 <_IO_stdin_used+0x6b8>
    48f1:	00 
    48f2:	0f 2f c8             	comiss %xmm0,%xmm1
    48f5:	76 38                	jbe    492f <susan_edges+0x10cf>
    48f7:	8b 54 24 68          	mov    0x68(%rsp),%edx
    48fb:	be 02 00 00 00       	mov    $0x2,%esi
    4900:	31 c0                	xor    %eax,%eax
    4902:	b9 01 00 00 00       	mov    $0x1,%ecx
    4907:	e9 a2 fd ff ff       	jmp    46ae <susan_edges+0xe4e>
    490c:	f3 0f 10 2d a8 2d 00 	movss  0x2da8(%rip),%xmm5        # 76bc <_IO_stdin_used+0x6bc>
    4913:	00 
    4914:	0f 2f e8             	comiss %xmm0,%xmm5
    4917:	0f 86 c0 00 00 00    	jbe    49dd <susan_edges+0x117d>
    491d:	8b 54 24 64          	mov    0x64(%rsp),%edx
    4921:	31 f6                	xor    %esi,%esi
    4923:	b8 01 00 00 00       	mov    $0x1,%eax
    4928:	31 c9                	xor    %ecx,%ecx
    492a:	e9 7f fd ff ff       	jmp    46ae <susan_edges+0xe4e>
    492f:	8b 84 24 68 01 00 00 	mov    0x168(%rsp),%eax
    4936:	8b 8c 24 c0 00 00 00 	mov    0xc0(%rsp),%ecx
    493d:	be fe ff ff ff       	mov    $0xfffffffe,%esi
    4942:	8d 54 08 01          	lea    0x1(%rax,%rcx,1),%edx
    4946:	b8 01 00 00 00       	mov    $0x1,%eax
    494b:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    4950:	e9 59 fd ff ff       	jmp    46ae <susan_edges+0xe4e>
    4955:	4c 89 8c 24 c8 01 00 	mov    %r9,0x1c8(%rsp)
    495c:	00 
    495d:	89 8c 24 c4 01 00 00 	mov    %ecx,0x1c4(%rsp)
    4964:	89 94 24 c0 01 00 00 	mov    %edx,0x1c0(%rsp)
    496b:	89 b4 24 bc 01 00 00 	mov    %esi,0x1bc(%rsp)
    4972:	89 bc 24 b8 01 00 00 	mov    %edi,0x1b8(%rsp)
    4979:	89 84 24 b4 01 00 00 	mov    %eax,0x1b4(%rsp)
    4980:	44 89 94 24 44 01 00 	mov    %r10d,0x144(%rsp)
    4987:	00 
    4988:	e8 a3 c8 ff ff       	call   1230 <sqrtf@plt>
    498d:	48 8b 05 04 2d 00 00 	mov    0x2d04(%rip),%rax        # 7698 <_IO_stdin_used+0x698>
    4994:	66 0f ef e4          	pxor   %xmm4,%xmm4
    4998:	4c 8b 8c 24 c8 01 00 	mov    0x1c8(%rsp),%r9
    499f:	00 
    49a0:	f3 0f 10 15 14 2d 00 	movss  0x2d14(%rip),%xmm2        # 76bc <_IO_stdin_used+0x6bc>
    49a7:	00 
    49a8:	8b 8c 24 c4 01 00 00 	mov    0x1c4(%rsp),%ecx
    49af:	66 48 0f 6e d8       	movq   %rax,%xmm3
    49b4:	8b 94 24 c0 01 00 00 	mov    0x1c0(%rsp),%edx
    49bb:	8b b4 24 bc 01 00 00 	mov    0x1bc(%rsp),%esi
    49c2:	8b bc 24 b8 01 00 00 	mov    0x1b8(%rsp),%edi
    49c9:	8b 84 24 b4 01 00 00 	mov    0x1b4(%rsp),%eax
    49d0:	44 8b 94 24 44 01 00 	mov    0x144(%rsp),%r10d
    49d7:	00 
    49d8:	e9 98 fc ff ff       	jmp    4675 <susan_edges+0xe15>
    49dd:	31 c0                	xor    %eax,%eax
    49df:	0f 2f 05 da 2c 00 00 	comiss 0x2cda(%rip),%xmm0        # 76c0 <_IO_stdin_used+0x6c0>
    49e6:	0f 96 c0             	setbe  %al
    49e9:	e9 af fc ff ff       	jmp    469d <susan_edges+0xe3d>
    49ee:	8b 44 24 68          	mov    0x68(%rsp),%eax
    49f2:	31 f6                	xor    %esi,%esi
    49f4:	bf 02 00 00 00       	mov    $0x2,%edi
    49f9:	31 d2                	xor    %edx,%edx
    49fb:	b9 01 00 00 00       	mov    $0x1,%ecx
    4a00:	e9 ab f4 ff ff       	jmp    3eb0 <susan_edges+0x650>
    4a05:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    4a0c:	00 00 00 00 

0000000000004a10 <susan_edges_small>:
    4a10:	f3 0f 1e fa          	endbr64 
    4a14:	41 57                	push   %r15
    4a16:	49 89 f7             	mov    %rsi,%r15
    4a19:	41 56                	push   %r14
    4a1b:	45 89 ce             	mov    %r9d,%r14d
    4a1e:	41 55                	push   %r13
    4a20:	41 54                	push   %r12
    4a22:	55                   	push   %rbp
    4a23:	48 89 fd             	mov    %rdi,%rbp
    4a26:	53                   	push   %rbx
    4a27:	48 89 cb             	mov    %rcx,%rbx
    4a2a:	48 81 ec b8 00 00 00 	sub    $0xb8,%rsp
    4a31:	48 89 54 24 18       	mov    %rdx,0x18(%rsp)
    4a36:	8b 94 24 f0 00 00 00 	mov    0xf0(%rsp),%edx
    4a3d:	48 89 7c 24 68       	mov    %rdi,0x68(%rsp)
    4a42:	4c 89 ff             	mov    %r15,%rdi
    4a45:	41 0f af d1          	imul   %r9d,%edx
    4a49:	48 89 74 24 40       	mov    %rsi,0x40(%rsp)
    4a4e:	31 f6                	xor    %esi,%esi
    4a50:	48 89 4c 24 48       	mov    %rcx,0x48(%rsp)
    4a55:	44 89 4c 24 50       	mov    %r9d,0x50(%rsp)
    4a5a:	48 63 d2             	movslq %edx,%rdx
    4a5d:	48 c1 e2 02          	shl    $0x2,%rdx
    4a61:	e8 7a c7 ff ff       	call   11e0 <memset@plt>
    4a66:	8b 84 24 f0 00 00 00 	mov    0xf0(%rsp),%eax
    4a6d:	83 e8 01             	sub    $0x1,%eax
    4a70:	89 44 24 0c          	mov    %eax,0xc(%rsp)
    4a74:	83 f8 01             	cmp    $0x1,%eax
    4a77:	0f 8e 0f 01 00 00    	jle    4b8c <susan_edges_small+0x17c>
    4a7d:	41 83 fe 02          	cmp    $0x2,%r14d
    4a81:	0f 8e 05 01 00 00    	jle    4b8c <susan_edges_small+0x17c>
    4a87:	4d 63 ce             	movslq %r14d,%r9
    4a8a:	45 8d 5e fd          	lea    -0x3(%r14),%r11d
    4a8e:	45 31 e4             	xor    %r12d,%r12d
    4a91:	41 bd 01 00 00 00    	mov    $0x1,%r13d
    4a97:	4f 8d 3c 8f          	lea    (%r15,%r9,4),%r15
    4a9b:	4e 8d 54 0d 00       	lea    0x0(%rbp,%r9,1),%r10
    4aa0:	49 83 c3 02          	add    $0x2,%r11
    4aa4:	bd da 02 00 00       	mov    $0x2da,%ebp
    4aa9:	4c 89 7c 24 10       	mov    %r15,0x10(%rsp)
    4aae:	4f 8d 44 09 fe       	lea    -0x2(%r9,%r9,1),%r8
    4ab3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    4ab8:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
    4abd:	b9 01 00 00 00       	mov    $0x1,%ecx
    4ac2:	4a 8d 14 20          	lea    (%rax,%r12,1),%rdx
    4ac6:	48 8b 44 24 10       	mov    0x10(%rsp),%rax
    4acb:	4e 8d 34 a0          	lea    (%rax,%r12,4),%r14
    4acf:	90                   	nop
    4ad0:	41 0f b6 04 0a       	movzbl (%r10,%rcx,1),%eax
    4ad5:	0f b6 3a             	movzbl (%rdx),%edi
    4ad8:	44 0f b6 7a 01       	movzbl 0x1(%rdx),%r15d
    4add:	48 01 d8             	add    %rbx,%rax
    4ae0:	48 89 c6             	mov    %rax,%rsi
    4ae3:	48 29 fe             	sub    %rdi,%rsi
    4ae6:	0f b6 3e             	movzbl (%rsi),%edi
    4ae9:	48 89 c6             	mov    %rax,%rsi
    4aec:	4c 29 fe             	sub    %r15,%rsi
    4aef:	44 0f b6 7a 02       	movzbl 0x2(%rdx),%r15d
    4af4:	0f b6 36             	movzbl (%rsi),%esi
    4af7:	8d 7c 37 64          	lea    0x64(%rdi,%rsi,1),%edi
    4afb:	48 89 c6             	mov    %rax,%rsi
    4afe:	4c 29 fe             	sub    %r15,%rsi
    4b01:	46 0f b6 3c 0a       	movzbl (%rdx,%r9,1),%r15d
    4b06:	0f b6 36             	movzbl (%rsi),%esi
    4b09:	01 fe                	add    %edi,%esi
    4b0b:	48 89 c7             	mov    %rax,%rdi
    4b0e:	4c 29 ff             	sub    %r15,%rdi
    4b11:	46 0f b6 7c 0a 02    	movzbl 0x2(%rdx,%r9,1),%r15d
    4b17:	0f b6 3f             	movzbl (%rdi),%edi
    4b1a:	01 f7                	add    %esi,%edi
    4b1c:	48 89 c6             	mov    %rax,%rsi
    4b1f:	4c 29 fe             	sub    %r15,%rsi
    4b22:	46 0f b6 7c 02 02    	movzbl 0x2(%rdx,%r8,1),%r15d
    4b28:	0f b6 36             	movzbl (%rsi),%esi
    4b2b:	01 fe                	add    %edi,%esi
    4b2d:	48 89 c7             	mov    %rax,%rdi
    4b30:	4c 29 ff             	sub    %r15,%rdi
    4b33:	46 0f b6 7c 02 03    	movzbl 0x3(%rdx,%r8,1),%r15d
    4b39:	0f b6 3f             	movzbl (%rdi),%edi
    4b3c:	01 f7                	add    %esi,%edi
    4b3e:	48 89 c6             	mov    %rax,%rsi
    4b41:	4c 29 fe             	sub    %r15,%rsi
    4b44:	0f b6 36             	movzbl (%rsi),%esi
    4b47:	01 fe                	add    %edi,%esi
    4b49:	42 0f b6 7c 02 04    	movzbl 0x4(%rdx,%r8,1),%edi
    4b4f:	48 29 f8             	sub    %rdi,%rax
    4b52:	0f b6 00             	movzbl (%rax),%eax
    4b55:	01 f0                	add    %esi,%eax
    4b57:	3d da 02 00 00       	cmp    $0x2da,%eax
    4b5c:	7f 08                	jg     4b66 <susan_edges_small+0x156>
    4b5e:	89 ee                	mov    %ebp,%esi
    4b60:	29 c6                	sub    %eax,%esi
    4b62:	41 89 34 8e          	mov    %esi,(%r14,%rcx,4)
    4b66:	48 83 c1 01          	add    $0x1,%rcx
    4b6a:	48 83 c2 01          	add    $0x1,%rdx
    4b6e:	49 39 cb             	cmp    %rcx,%r11
    4b71:	0f 85 59 ff ff ff    	jne    4ad0 <susan_edges_small+0xc0>
    4b77:	41 83 c5 01          	add    $0x1,%r13d
    4b7b:	4d 01 cc             	add    %r9,%r12
    4b7e:	4d 01 ca             	add    %r9,%r10
    4b81:	44 3b 6c 24 0c       	cmp    0xc(%rsp),%r13d
    4b86:	0f 85 2c ff ff ff    	jne    4ab8 <susan_edges_small+0xa8>
    4b8c:	8b 84 24 f0 00 00 00 	mov    0xf0(%rsp),%eax
    4b93:	83 e8 02             	sub    $0x2,%eax
    4b96:	89 84 24 80 00 00 00 	mov    %eax,0x80(%rsp)
    4b9d:	83 f8 02             	cmp    $0x2,%eax
    4ba0:	0f 8e 6f 03 00 00    	jle    4f15 <susan_edges_small+0x505>
    4ba6:	8b 5c 24 50          	mov    0x50(%rsp),%ebx
    4baa:	83 fb 04             	cmp    $0x4,%ebx
    4bad:	0f 8e 62 03 00 00    	jle    4f15 <susan_edges_small+0x505>
    4bb3:	8d 14 1b             	lea    (%rbx,%rbx,1),%edx
    4bb6:	48 8b 4c 24 18       	mov    0x18(%rsp),%rcx
    4bbb:	4c 63 db             	movslq %ebx,%r11
    4bbe:	89 5c 24 70          	mov    %ebx,0x70(%rsp)
    4bc2:	48 63 c2             	movslq %edx,%rax
    4bc5:	01 da                	add    %ebx,%edx
    4bc7:	66 0f ef e4          	pxor   %xmm4,%xmm4
    4bcb:	4d 89 d8             	mov    %r11,%r8
    4bce:	48 01 c1             	add    %rax,%rcx
    4bd1:	89 54 24 74          	mov    %edx,0x74(%rsp)
    4bd5:	f3 0f 10 15 df 2a 00 	movss  0x2adf(%rip),%xmm2        # 76bc <_IO_stdin_used+0x6bc>
    4bdc:	00 
    4bdd:	48 89 4c 24 60       	mov    %rcx,0x60(%rsp)
    4be2:	48 8b 4c 24 68       	mov    0x68(%rsp),%rcx
    4be7:	c7 44 24 5c 02 00 00 	movl   $0x2,0x5c(%rsp)
    4bee:	00 
    4bef:	48 01 c1             	add    %rax,%rcx
    4bf2:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
    4bf7:	4a 8d 0c 9d 00 00 00 	lea    0x0(,%r11,4),%rcx
    4bfe:	00 
    4bff:	48 89 4c 24 78       	mov    %rcx,0x78(%rsp)
    4c04:	48 8b 4c 24 40       	mov    0x40(%rsp),%rcx
    4c09:	48 8d 04 81          	lea    (%rcx,%rax,4),%rax
    4c0d:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    4c12:	8d 43 03             	lea    0x3(%rbx),%eax
    4c15:	89 84 24 84 00 00 00 	mov    %eax,0x84(%rsp)
    4c1c:	8d 43 fb             	lea    -0x5(%rbx),%eax
    4c1f:	48 83 c0 03          	add    $0x3,%rax
    4c23:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    4c28:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    4c2f:	00 
    4c30:	8b 44 24 5c          	mov    0x5c(%rsp),%eax
    4c34:	8b 5c 24 70          	mov    0x70(%rsp),%ebx
    4c38:	41 b9 02 00 00 00    	mov    $0x2,%r9d
    4c3e:	8b 4c 24 50          	mov    0x50(%rsp),%ecx
    4c42:	f2 0f 10 1d 56 2a 00 	movsd  0x2a56(%rip),%xmm3        # 76a0 <_IO_stdin_used+0x6a0>
    4c49:	00 
    4c4a:	89 44 24 54          	mov    %eax,0x54(%rsp)
    4c4e:	83 c0 01             	add    $0x1,%eax
    4c51:	89 44 24 5c          	mov    %eax,0x5c(%rsp)
    4c55:	48 63 c3             	movslq %ebx,%rax
    4c58:	01 cb                	add    %ecx,%ebx
    4c5a:	8b 4c 24 74          	mov    0x74(%rsp),%ecx
    4c5e:	89 5c 24 70          	mov    %ebx,0x70(%rsp)
    4c62:	8b 9c 24 84 00 00 00 	mov    0x84(%rsp),%ebx
    4c69:	8d 71 02             	lea    0x2(%rcx),%esi
    4c6c:	8d 48 03             	lea    0x3(%rax),%ecx
    4c6f:	89 4c 24 10          	mov    %ecx,0x10(%rsp)
    4c73:	48 8b 4c 24 68       	mov    0x68(%rsp),%rcx
    4c78:	01 c3                	add    %eax,%ebx
    4c7a:	41 89 de             	mov    %ebx,%r14d
    4c7d:	4c 8d 5c 01 01       	lea    0x1(%rcx,%rax,1),%r11
    4c82:	eb 5a                	jmp    4cde <susan_edges_small+0x2ce>
    4c84:	0f 1f 40 00          	nopl   0x0(%rax)
    4c88:	48 63 c6             	movslq %esi,%rax
    4c8b:	bf 01 00 00 00       	mov    $0x1,%edi
    4c90:	8d 50 01             	lea    0x1(%rax),%edx
    4c93:	48 8b 5c 24 40       	mov    0x40(%rsp),%rbx
    4c98:	3b 2c 83             	cmp    (%rbx,%rax,4),%ebp
    4c9b:	7e 23                	jle    4cc0 <susan_edges_small+0x2b0>
    4c9d:	8b 44 24 54          	mov    0x54(%rsp),%eax
    4ca1:	29 f8                	sub    %edi,%eax
    4ca3:	0f af 44 24 50       	imul   0x50(%rsp),%eax
    4ca8:	03 44 24 0c          	add    0xc(%rsp),%eax
    4cac:	29 c8                	sub    %ecx,%eax
    4cae:	48 98                	cltq   
    4cb0:	3b 2c 83             	cmp    (%rbx,%rax,4),%ebp
    4cb3:	7c 0b                	jl     4cc0 <susan_edges_small+0x2b0>
    4cb5:	48 8b 44 24 60       	mov    0x60(%rsp),%rax
    4cba:	42 c6 04 08 02       	movb   $0x2,(%rax,%r9,1)
    4cbf:	90                   	nop
    4cc0:	83 44 24 10 01       	addl   $0x1,0x10(%rsp)
    4cc5:	49 83 c1 01          	add    $0x1,%r9
    4cc9:	41 83 c6 01          	add    $0x1,%r14d
    4ccd:	89 d6                	mov    %edx,%esi
    4ccf:	49 83 c3 01          	add    $0x1,%r11
    4cd3:	4c 39 4c 24 28       	cmp    %r9,0x28(%rsp)
    4cd8:	0f 84 0a 02 00 00    	je     4ee8 <susan_edges_small+0x4d8>
    4cde:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
    4ce3:	44 89 4c 24 0c       	mov    %r9d,0xc(%rsp)
    4ce8:	8d 56 01             	lea    0x1(%rsi),%edx
    4ceb:	42 8b 2c 88          	mov    (%rax,%r9,4),%ebp
    4cef:	85 ed                	test   %ebp,%ebp
    4cf1:	7e cd                	jle    4cc0 <susan_edges_small+0x2b0>
    4cf3:	b8 da 02 00 00       	mov    $0x2da,%eax
    4cf8:	41 0f b6 13          	movzbl (%r11),%edx
    4cfc:	43 0f b6 0c 03       	movzbl (%r11,%r8,1),%ecx
    4d01:	29 e8                	sub    %ebp,%eax
    4d03:	47 0f b6 54 43 01    	movzbl 0x1(%r11,%r8,2),%r10d
    4d09:	89 44 24 34          	mov    %eax,0x34(%rsp)
    4d0d:	41 89 c7             	mov    %eax,%r15d
    4d10:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    4d15:	42 0f b6 3c 08       	movzbl (%rax,%r9,1),%edi
    4d1a:	48 03 7c 24 48       	add    0x48(%rsp),%rdi
    4d1f:	48 89 f8             	mov    %rdi,%rax
    4d22:	48 29 d0             	sub    %rdx,%rax
    4d25:	41 0f b6 53 01       	movzbl 0x1(%r11),%edx
    4d2a:	44 0f b6 20          	movzbl (%rax),%r12d
    4d2e:	48 89 f8             	mov    %rdi,%rax
    4d31:	48 29 d0             	sub    %rdx,%rax
    4d34:	41 0f b6 53 02       	movzbl 0x2(%r11),%edx
    4d39:	0f b6 18             	movzbl (%rax),%ebx
    4d3c:	48 89 f8             	mov    %rdi,%rax
    4d3f:	48 29 d0             	sub    %rdx,%rax
    4d42:	0f b6 10             	movzbl (%rax),%edx
    4d45:	48 89 f8             	mov    %rdi,%rax
    4d48:	48 29 c8             	sub    %rcx,%rax
    4d4b:	43 0f b6 4c 03 02    	movzbl 0x2(%r11,%r8,1),%ecx
    4d51:	0f b6 00             	movzbl (%rax),%eax
    4d54:	89 44 24 18          	mov    %eax,0x18(%rsp)
    4d58:	48 89 f8             	mov    %rdi,%rax
    4d5b:	48 29 c8             	sub    %rcx,%rax
    4d5e:	43 0f b6 0c 43       	movzbl (%r11,%r8,2),%ecx
    4d63:	0f b6 00             	movzbl (%rax),%eax
    4d66:	89 44 24 30          	mov    %eax,0x30(%rsp)
    4d6a:	48 89 f8             	mov    %rdi,%rax
    4d6d:	48 29 c8             	sub    %rcx,%rax
    4d70:	48 89 f9             	mov    %rdi,%rcx
    4d73:	4c 29 d1             	sub    %r10,%rcx
    4d76:	47 0f b6 54 43 02    	movzbl 0x2(%r11,%r8,2),%r10d
    4d7c:	0f b6 00             	movzbl (%rax),%eax
    4d7f:	0f b6 09             	movzbl (%rcx),%ecx
    4d82:	4c 29 d7             	sub    %r10,%rdi
    4d85:	44 0f b6 17          	movzbl (%rdi),%r10d
    4d89:	41 81 ff fa 00 00 00 	cmp    $0xfa,%r15d
    4d90:	7f 56                	jg     4de8 <susan_edges_small+0x3d8>
    4d92:	44 01 e3             	add    %r12d,%ebx
    4d95:	01 d3                	add    %edx,%ebx
    4d97:	01 c3                	add    %eax,%ebx
    4d99:	01 d9                	add    %ebx,%ecx
    4d9b:	44 01 d1             	add    %r10d,%ecx
    4d9e:	0f 84 e4 fe ff ff    	je     4c88 <susan_edges_small+0x278>
    4da4:	41 8d 3c 14          	lea    (%r12,%rdx,1),%edi
    4da8:	66 0f ef c0          	pxor   %xmm0,%xmm0
    4dac:	66 0f ef c9          	pxor   %xmm1,%xmm1
    4db0:	03 7c 24 18          	add    0x18(%rsp),%edi
    4db4:	03 7c 24 30          	add    0x30(%rsp),%edi
    4db8:	f3 0f 2a c9          	cvtsi2ss %ecx,%xmm1
    4dbc:	01 c7                	add    %eax,%edi
    4dbe:	44 01 d7             	add    %r10d,%edi
    4dc1:	f3 0f 2a c7          	cvtsi2ss %edi,%xmm0
    4dc5:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    4dc9:	0f 2f d0             	comiss %xmm0,%xmm2
    4dcc:	0f 86 de 00 00 00    	jbe    4eb0 <susan_edges_small+0x4a0>
    4dd2:	49 63 c6             	movslq %r14d,%rax
    4dd5:	b9 01 00 00 00       	mov    $0x1,%ecx
    4dda:	8d 56 01             	lea    0x1(%rsi),%edx
    4ddd:	31 ff                	xor    %edi,%edi
    4ddf:	e9 af fe ff ff       	jmp    4c93 <susan_edges_small+0x283>
    4de4:	0f 1f 40 00          	nopl   0x0(%rax)
    4de8:	41 89 d7             	mov    %edx,%r15d
    4deb:	45 89 e5             	mov    %r12d,%r13d
    4dee:	66 0f ef c0          	pxor   %xmm0,%xmm0
    4df2:	45 29 e7             	sub    %r12d,%r15d
    4df5:	44 2b 7c 24 18       	sub    0x18(%rsp),%r15d
    4dfa:	44 03 7c 24 30       	add    0x30(%rsp),%r15d
    4dff:	41 f7 dd             	neg    %r13d
    4e02:	41 29 c7             	sub    %eax,%r15d
    4e05:	41 29 dd             	sub    %ebx,%r13d
    4e08:	45 01 d7             	add    %r10d,%r15d
    4e0b:	41 29 d5             	sub    %edx,%r13d
    4e0e:	44 89 ff             	mov    %r15d,%edi
    4e11:	41 01 c5             	add    %eax,%r13d
    4e14:	41 0f af ff          	imul   %r15d,%edi
    4e18:	41 01 cd             	add    %ecx,%r13d
    4e1b:	45 01 d5             	add    %r10d,%r13d
    4e1e:	89 7c 24 58          	mov    %edi,0x58(%rsp)
    4e22:	44 89 ef             	mov    %r13d,%edi
    4e25:	41 0f af fd          	imul   %r13d,%edi
    4e29:	03 7c 24 58          	add    0x58(%rsp),%edi
    4e2d:	f3 0f 2a c7          	cvtsi2ss %edi,%xmm0
    4e31:	0f 2e e0             	ucomiss %xmm0,%xmm4
    4e34:	0f 87 83 01 00 00    	ja     4fbd <susan_edges_small+0x5ad>
    4e3a:	f3 0f 51 c0          	sqrtss %xmm0,%xmm0
    4e3e:	66 0f ef c9          	pxor   %xmm1,%xmm1
    4e42:	f3 0f 5a c0          	cvtss2sd %xmm0,%xmm0
    4e46:	f3 0f 2a 4c 24 34    	cvtsi2ssl 0x34(%rsp),%xmm1
    4e4c:	f3 0f 5a c9          	cvtss2sd %xmm1,%xmm1
    4e50:	f2 0f 59 cb          	mulsd  %xmm3,%xmm1
    4e54:	66 0f 2f c1          	comisd %xmm1,%xmm0
    4e58:	0f 86 34 ff ff ff    	jbe    4d92 <susan_edges_small+0x382>
    4e5e:	45 85 ff             	test   %r15d,%r15d
    4e61:	0f 85 e1 00 00 00    	jne    4f48 <susan_edges_small+0x538>
    4e67:	42 8d 04 3e          	lea    (%rsi,%r15,1),%eax
    4e6b:	b9 01 00 00 00       	mov    $0x1,%ecx
    4e70:	48 8b 5c 24 40       	mov    0x40(%rsp),%rbx
    4e75:	48 98                	cltq   
    4e77:	8d 56 01             	lea    0x1(%rsi),%edx
    4e7a:	3b 2c 83             	cmp    (%rbx,%rax,4),%ebp
    4e7d:	0f 8e 3d fe ff ff    	jle    4cc0 <susan_edges_small+0x2b0>
    4e83:	8b 44 24 54          	mov    0x54(%rsp),%eax
    4e87:	29 c8                	sub    %ecx,%eax
    4e89:	0f af 44 24 50       	imul   0x50(%rsp),%eax
    4e8e:	03 44 24 0c          	add    0xc(%rsp),%eax
    4e92:	44 29 f8             	sub    %r15d,%eax
    4e95:	48 98                	cltq   
    4e97:	3b 2c 83             	cmp    (%rbx,%rax,4),%ebp
    4e9a:	0f 8c 20 fe ff ff    	jl     4cc0 <susan_edges_small+0x2b0>
    4ea0:	48 8b 44 24 60       	mov    0x60(%rsp),%rax
    4ea5:	42 c6 04 08 01       	movb   $0x1,(%rax,%r9,1)
    4eaa:	e9 11 fe ff ff       	jmp    4cc0 <susan_edges_small+0x2b0>
    4eaf:	90                   	nop
    4eb0:	0f 2f 05 09 28 00 00 	comiss 0x2809(%rip),%xmm0        # 76c0 <_IO_stdin_used+0x6c0>
    4eb7:	0f 87 a7 01 00 00    	ja     5064 <susan_edges_small+0x654>
    4ebd:	41 29 d4             	sub    %edx,%r12d
    4ec0:	41 29 c4             	sub    %eax,%r12d
    4ec3:	45 01 d4             	add    %r10d,%r12d
    4ec6:	45 85 e4             	test   %r12d,%r12d
    4ec9:	7e 65                	jle    4f30 <susan_edges_small+0x520>
    4ecb:	48 63 44 24 10       	movslq 0x10(%rsp),%rax
    4ed0:	b9 01 00 00 00       	mov    $0x1,%ecx
    4ed5:	bf ff ff ff ff       	mov    $0xffffffff,%edi
    4eda:	8d 56 01             	lea    0x1(%rsi),%edx
    4edd:	e9 b1 fd ff ff       	jmp    4c93 <susan_edges_small+0x283>
    4ee2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    4ee8:	8b 5c 24 50          	mov    0x50(%rsp),%ebx
    4eec:	4c 01 44 24 60       	add    %r8,0x60(%rsp)
    4ef1:	01 5c 24 74          	add    %ebx,0x74(%rsp)
    4ef5:	48 8b 5c 24 78       	mov    0x78(%rsp),%rbx
    4efa:	4c 01 44 24 38       	add    %r8,0x38(%rsp)
    4eff:	48 01 5c 24 20       	add    %rbx,0x20(%rsp)
    4f04:	8b 5c 24 5c          	mov    0x5c(%rsp),%ebx
    4f08:	39 9c 24 80 00 00 00 	cmp    %ebx,0x80(%rsp)
    4f0f:	0f 85 1b fd ff ff    	jne    4c30 <susan_edges_small+0x220>
    4f15:	48 81 c4 b8 00 00 00 	add    $0xb8,%rsp
    4f1c:	5b                   	pop    %rbx
    4f1d:	5d                   	pop    %rbp
    4f1e:	41 5c                	pop    %r12
    4f20:	41 5d                	pop    %r13
    4f22:	41 5e                	pop    %r14
    4f24:	41 5f                	pop    %r15
    4f26:	c3                   	ret    
    4f27:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    4f2e:	00 00 
    4f30:	8d 56 01             	lea    0x1(%rsi),%edx
    4f33:	b9 01 00 00 00       	mov    $0x1,%ecx
    4f38:	bf 01 00 00 00       	mov    $0x1,%edi
    4f3d:	48 63 c2             	movslq %edx,%rax
    4f40:	e9 4e fd ff ff       	jmp    4c93 <susan_edges_small+0x283>
    4f45:	0f 1f 00             	nopl   (%rax)
    4f48:	66 0f ef c0          	pxor   %xmm0,%xmm0
    4f4c:	66 0f ef c9          	pxor   %xmm1,%xmm1
    4f50:	f3 41 0f 2a c5       	cvtsi2ss %r13d,%xmm0
    4f55:	f3 41 0f 2a cf       	cvtsi2ss %r15d,%xmm1
    4f5a:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    4f5e:	0f 2f e0             	comiss %xmm0,%xmm4
    4f61:	76 25                	jbe    4f88 <susan_edges_small+0x578>
    4f63:	0f 2f 05 4a 27 00 00 	comiss 0x274a(%rip),%xmm0        # 76b4 <_IO_stdin_used+0x6b4>
    4f6a:	77 2d                	ja     4f99 <susan_edges_small+0x589>
    4f6c:	f3 0f 10 0d 44 27 00 	movss  0x2744(%rip),%xmm1        # 76b8 <_IO_stdin_used+0x6b8>
    4f73:	00 
    4f74:	0f 2f c8             	comiss %xmm0,%xmm1
    4f77:	76 30                	jbe    4fa9 <susan_edges_small+0x599>
    4f79:	89 f0                	mov    %esi,%eax
    4f7b:	45 31 ff             	xor    %r15d,%r15d
    4f7e:	b9 01 00 00 00       	mov    $0x1,%ecx
    4f83:	e9 e8 fe ff ff       	jmp    4e70 <susan_edges_small+0x460>
    4f88:	f3 0f 10 2d 2c 27 00 	movss  0x272c(%rip),%xmm5        # 76bc <_IO_stdin_used+0x6bc>
    4f8f:	00 
    4f90:	0f 2f e8             	comiss %xmm0,%xmm5
    4f93:	0f 86 b8 00 00 00    	jbe    5051 <susan_edges_small+0x641>
    4f99:	44 89 f0             	mov    %r14d,%eax
    4f9c:	41 bf 01 00 00 00    	mov    $0x1,%r15d
    4fa2:	31 c9                	xor    %ecx,%ecx
    4fa4:	e9 c7 fe ff ff       	jmp    4e70 <susan_edges_small+0x460>
    4fa9:	8b 44 24 10          	mov    0x10(%rsp),%eax
    4fad:	41 bf 01 00 00 00    	mov    $0x1,%r15d
    4fb3:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    4fb8:	e9 b3 fe ff ff       	jmp    4e70 <susan_edges_small+0x460>
    4fbd:	4c 89 8c 24 a8 00 00 	mov    %r9,0xa8(%rsp)
    4fc4:	00 
    4fc5:	4c 89 9c 24 a0 00 00 	mov    %r11,0xa0(%rsp)
    4fcc:	00 
    4fcd:	4c 89 84 24 98 00 00 	mov    %r8,0x98(%rsp)
    4fd4:	00 
    4fd5:	89 b4 24 94 00 00 00 	mov    %esi,0x94(%rsp)
    4fdc:	44 89 94 24 90 00 00 	mov    %r10d,0x90(%rsp)
    4fe3:	00 
    4fe4:	89 8c 24 8c 00 00 00 	mov    %ecx,0x8c(%rsp)
    4feb:	89 84 24 88 00 00 00 	mov    %eax,0x88(%rsp)
    4ff2:	89 54 24 58          	mov    %edx,0x58(%rsp)
    4ff6:	e8 35 c2 ff ff       	call   1230 <sqrtf@plt>
    4ffb:	48 8b 05 9e 26 00 00 	mov    0x269e(%rip),%rax        # 76a0 <_IO_stdin_used+0x6a0>
    5002:	4c 8b 8c 24 a8 00 00 	mov    0xa8(%rsp),%r9
    5009:	00 
    500a:	66 0f ef e4          	pxor   %xmm4,%xmm4
    500e:	4c 8b 9c 24 a0 00 00 	mov    0xa0(%rsp),%r11
    5015:	00 
    5016:	4c 8b 84 24 98 00 00 	mov    0x98(%rsp),%r8
    501d:	00 
    501e:	66 48 0f 6e d8       	movq   %rax,%xmm3
    5023:	8b b4 24 94 00 00 00 	mov    0x94(%rsp),%esi
    502a:	f3 0f 10 15 8a 26 00 	movss  0x268a(%rip),%xmm2        # 76bc <_IO_stdin_used+0x6bc>
    5031:	00 
    5032:	44 8b 94 24 90 00 00 	mov    0x90(%rsp),%r10d
    5039:	00 
    503a:	8b 8c 24 8c 00 00 00 	mov    0x8c(%rsp),%ecx
    5041:	8b 84 24 88 00 00 00 	mov    0x88(%rsp),%eax
    5048:	8b 54 24 58          	mov    0x58(%rsp),%edx
    504c:	e9 ed fd ff ff       	jmp    4e3e <susan_edges_small+0x42e>
    5051:	45 31 ff             	xor    %r15d,%r15d
    5054:	0f 2f 05 65 26 00 00 	comiss 0x2665(%rip),%xmm0        # 76c0 <_IO_stdin_used+0x6c0>
    505b:	41 0f 96 c7          	setbe  %r15b
    505f:	e9 03 fe ff ff       	jmp    4e67 <susan_edges_small+0x457>
    5064:	48 63 c6             	movslq %esi,%rax
    5067:	31 c9                	xor    %ecx,%ecx
    5069:	bf 01 00 00 00       	mov    $0x1,%edi
    506e:	8d 50 01             	lea    0x1(%rax),%edx
    5071:	e9 1d fc ff ff       	jmp    4c93 <susan_edges_small+0x283>
    5076:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    507d:	00 00 00 

0000000000005080 <corner_draw>:
    5080:	f3 0f 1e fa          	endbr64 
    5084:	83 7e 08 07          	cmpl   $0x7,0x8(%rsi)
    5088:	41 89 d0             	mov    %edx,%r8d
    508b:	74 2b                	je     50b8 <corner_draw+0x38>
    508d:	85 c9                	test   %ecx,%ecx
    508f:	74 2f                	je     50c0 <corner_draw+0x40>
    5091:	48 89 f0             	mov    %rsi,%rax
    5094:	83 fa 01             	cmp    $0x1,%edx
    5097:	0f 85 93 00 00 00    	jne    5130 <corner_draw+0xb0>
    509d:	0f 1f 00             	nopl   (%rax)
    50a0:	48 63 50 04          	movslq 0x4(%rax),%rdx
    50a4:	48 63 08             	movslq (%rax),%rcx
    50a7:	48 83 c0 18          	add    $0x18,%rax
    50ab:	48 01 fa             	add    %rdi,%rdx
    50ae:	c6 04 0a 00          	movb   $0x0,(%rdx,%rcx,1)
    50b2:	83 78 08 07          	cmpl   $0x7,0x8(%rax)
    50b6:	75 e8                	jne    50a0 <corner_draw+0x20>
    50b8:	31 c0                	xor    %eax,%eax
    50ba:	c3                   	ret    
    50bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    50c0:	48 63 d2             	movslq %edx,%rdx
    50c3:	48 83 ea 02          	sub    $0x2,%rdx
    50c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    50ce:	00 00 
    50d0:	8b 46 04             	mov    0x4(%rsi),%eax
    50d3:	48 63 0e             	movslq (%rsi),%rcx
    50d6:	41 b9 ff 00 00 00    	mov    $0xff,%r9d
    50dc:	48 83 c6 18          	add    $0x18,%rsi
    50e0:	41 ba ff ff ff ff    	mov    $0xffffffff,%r10d
    50e6:	83 e8 01             	sub    $0x1,%eax
    50e9:	41 0f af c0          	imul   %r8d,%eax
    50ed:	48 98                	cltq   
    50ef:	48 8d 44 08 ff       	lea    -0x1(%rax,%rcx,1),%rax
    50f4:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    50f9:	48 01 f8             	add    %rdi,%rax
    50fc:	66 89 08             	mov    %cx,(%rax)
    50ff:	c6 40 02 ff          	movb   $0xff,0x2(%rax)
    5103:	48 8d 44 10 02       	lea    0x2(%rax,%rdx,1),%rax
    5108:	66 44 89 08          	mov    %r9w,(%rax)
    510c:	c6 40 02 ff          	movb   $0xff,0x2(%rax)
    5110:	48 8d 44 10 02       	lea    0x2(%rax,%rdx,1),%rax
    5115:	66 44 89 10          	mov    %r10w,(%rax)
    5119:	c6 40 02 ff          	movb   $0xff,0x2(%rax)
    511d:	83 7e 08 07          	cmpl   $0x7,0x8(%rsi)
    5121:	75 ad                	jne    50d0 <corner_draw+0x50>
    5123:	31 c0                	xor    %eax,%eax
    5125:	c3                   	ret    
    5126:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    512d:	00 00 00 
    5130:	8b 46 04             	mov    0x4(%rsi),%eax
    5133:	48 63 16             	movslq (%rsi),%rdx
    5136:	48 83 c6 18          	add    $0x18,%rsi
    513a:	41 0f af c0          	imul   %r8d,%eax
    513e:	48 98                	cltq   
    5140:	48 01 f8             	add    %rdi,%rax
    5143:	c6 04 10 00          	movb   $0x0,(%rax,%rdx,1)
    5147:	83 7e 08 07          	cmpl   $0x7,0x8(%rsi)
    514b:	75 e3                	jne    5130 <corner_draw+0xb0>
    514d:	e9 66 ff ff ff       	jmp    50b8 <corner_draw+0x38>
    5152:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    5159:	00 00 00 00 
    515d:	0f 1f 00             	nopl   (%rax)

0000000000005160 <susan_corners>:
    5160:	f3 0f 1e fa          	endbr64 
    5164:	41 57                	push   %r15
    5166:	41 56                	push   %r14
    5168:	41 55                	push   %r13
    516a:	49 89 f5             	mov    %rsi,%r13
    516d:	31 f6                	xor    %esi,%esi
    516f:	41 54                	push   %r12
    5171:	55                   	push   %rbp
    5172:	44 89 cd             	mov    %r9d,%ebp
    5175:	53                   	push   %rbx
    5176:	48 81 ec 38 01 00 00 	sub    $0x138,%rsp
    517d:	8b 9c 24 70 01 00 00 	mov    0x170(%rsp),%ebx
    5184:	48 89 7c 24 78       	mov    %rdi,0x78(%rsp)
    5189:	4c 89 ef             	mov    %r13,%rdi
    518c:	48 89 54 24 50       	mov    %rdx,0x50(%rsp)
    5191:	0f af eb             	imul   %ebx,%ebp
    5194:	89 4c 24 10          	mov    %ecx,0x10(%rsp)
    5198:	4c 89 84 24 e8 00 00 	mov    %r8,0xe8(%rsp)
    519f:	00 
    51a0:	44 89 8c 24 f4 00 00 	mov    %r9d,0xf4(%rsp)
    51a7:	00 
    51a8:	48 63 ed             	movslq %ebp,%rbp
    51ab:	48 c1 e5 02          	shl    $0x2,%rbp
    51af:	48 89 ea             	mov    %rbp,%rdx
    51b2:	e8 29 c0 ff ff       	call   11e0 <memset@plt>
    51b7:	48 89 ef             	mov    %rbp,%rdi
    51ba:	e8 81 c0 ff ff       	call   1240 <malloc@plt>
    51bf:	48 89 ef             	mov    %rbp,%rdi
    51c2:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
    51c7:	e8 74 c0 ff ff       	call   1240 <malloc@plt>
    51cc:	48 89 84 24 80 00 00 	mov    %rax,0x80(%rsp)
    51d3:	00 
    51d4:	8d 43 fb             	lea    -0x5(%rbx),%eax
    51d7:	89 44 24 74          	mov    %eax,0x74(%rsp)
    51db:	83 f8 05             	cmp    $0x5,%eax
    51de:	0f 8e 35 0d 00 00    	jle    5f19 <susan_corners+0xdb9>
    51e4:	8b b4 24 f4 00 00 00 	mov    0xf4(%rsp),%esi
    51eb:	8d 46 fb             	lea    -0x5(%rsi),%eax
    51ee:	89 84 24 94 00 00 00 	mov    %eax,0x94(%rsp)
    51f5:	83 f8 05             	cmp    $0x5,%eax
    51f8:	0f 8e 35 09 00 00    	jle    5b33 <susan_corners+0x9d3>
    51fe:	4c 8b 54 24 78       	mov    0x78(%rsp),%r10
    5203:	8d 04 36             	lea    (%rsi,%rsi,1),%eax
    5206:	48 63 fe             	movslq %esi,%rdi
    5209:	66 0f ef d2          	pxor   %xmm2,%xmm2
    520d:	48 98                	cltq   
    520f:	48 89 bc 24 a8 00 00 	mov    %rdi,0xa8(%rsp)
    5216:	00 
    5217:	f2 0f 10 25 89 24 00 	movsd  0x2489(%rip),%xmm4        # 76a8 <_IO_stdin_used+0x6a8>
    521e:	00 
    521f:	49 8d 14 42          	lea    (%r10,%rax,2),%rdx
    5223:	4c 89 ac 24 c0 00 00 	mov    %r13,0xc0(%rsp)
    522a:	00 
    522b:	48 89 54 24 38       	mov    %rdx,0x38(%rsp)
    5230:	48 8d 14 7f          	lea    (%rdi,%rdi,2),%rdx
    5234:	c7 84 24 90 00 00 00 	movl   $0x5,0x90(%rsp)
    523b:	05 00 00 00 
    523f:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
    5243:	48 8d 14 50          	lea    (%rax,%rdx,2),%rdx
    5247:	4c 01 d2             	add    %r10,%rdx
    524a:	49 8d 1c 0a          	lea    (%r10,%rcx,1),%rbx
    524e:	48 89 94 24 b0 00 00 	mov    %rdx,0xb0(%rsp)
    5255:	00 
    5256:	48 8d 14 bd 00 00 00 	lea    0x0(,%rdi,4),%rdx
    525d:	00 
    525e:	49 89 dd             	mov    %rbx,%r13
    5261:	48 89 94 24 c8 00 00 	mov    %rdx,0xc8(%rsp)
    5268:	00 
    5269:	48 01 fa             	add    %rdi,%rdx
    526c:	48 01 d0             	add    %rdx,%rax
    526f:	4c 01 d0             	add    %r10,%rax
    5272:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
    5279:	00 
    527a:	8d 04 b6             	lea    (%rsi,%rsi,4),%eax
    527d:	48 98                	cltq   
    527f:	48 c1 e0 02          	shl    $0x2,%rax
    5283:	48 89 84 24 a0 00 00 	mov    %rax,0xa0(%rsp)
    528a:	00 
    528b:	48 89 f8             	mov    %rdi,%rax
    528e:	48 f7 d8             	neg    %rax
    5291:	48 8d 44 00 04       	lea    0x4(%rax,%rax,1),%rax
    5296:	48 89 84 24 d0 00 00 	mov    %rax,0xd0(%rsp)
    529d:	00 
    529e:	8d 46 f5             	lea    -0xb(%rsi),%eax
    52a1:	89 84 24 f0 00 00 00 	mov    %eax,0xf0(%rsp)
    52a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    52af:	00 
    52b0:	48 8b 94 24 a8 00 00 	mov    0xa8(%rsp),%rdx
    52b7:	00 
    52b8:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
    52bd:	4d 8d 65 03          	lea    0x3(%r13),%r12
    52c1:	b8 03 00 00 00       	mov    $0x3,%eax
    52c6:	48 8b 9c 24 d0 00 00 	mov    0xd0(%rsp),%rbx
    52cd:	00 
    52ce:	41 ba 05 00 00 00    	mov    $0x5,%r10d
    52d4:	4d 89 e8             	mov    %r13,%r8
    52d7:	48 29 d0             	sub    %rdx,%rax
    52da:	4c 8d 5f 03          	lea    0x3(%rdi),%r11
    52de:	48 8d 2c 38          	lea    (%rax,%rdi,1),%rbp
    52e2:	48 03 84 24 98 00 00 	add    0x98(%rsp),%rax
    52e9:	00 
    52ea:	48 01 fb             	add    %rdi,%rbx
    52ed:	48 8b bc 24 a0 00 00 	mov    0xa0(%rsp),%rdi
    52f4:	00 
    52f5:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
    52fa:	8b 84 24 f0 00 00 00 	mov    0xf0(%rsp),%eax
    5301:	48 83 c0 06          	add    $0x6,%rax
    5305:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
    530a:	49 8d 44 15 00       	lea    0x0(%r13,%rdx,1),%rax
    530f:	48 89 84 24 88 00 00 	mov    %rax,0x88(%rsp)
    5316:	00 
    5317:	48 8b 84 24 c0 00 00 	mov    0xc0(%rsp),%rax
    531e:	00 
    531f:	48 01 f8             	add    %rdi,%rax
    5322:	48 89 84 24 d8 00 00 	mov    %rax,0xd8(%rsp)
    5329:	00 
    532a:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
    532f:	48 01 f8             	add    %rdi,%rax
    5332:	48 89 84 24 e0 00 00 	mov    %rax,0xe0(%rsp)
    5339:	00 
    533a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    5340:	0f b6 0b             	movzbl (%rbx),%ecx
    5343:	43 0f b6 14 10       	movzbl (%r8,%r10,1),%edx
    5348:	44 89 54 24 58       	mov    %r10d,0x58(%rsp)
    534d:	48 03 54 24 50       	add    0x50(%rsp),%rdx
    5352:	0f b6 73 02          	movzbl 0x2(%rbx),%esi
    5356:	48 89 d0             	mov    %rdx,%rax
    5359:	4c 8b 6c 24 38       	mov    0x38(%rsp),%r13
    535e:	48 29 c8             	sub    %rcx,%rax
    5361:	0f b6 4b 01          	movzbl 0x1(%rbx),%ecx
    5365:	0f b6 38             	movzbl (%rax),%edi
    5368:	48 89 d0             	mov    %rdx,%rax
    536b:	48 29 c8             	sub    %rcx,%rax
    536e:	48 89 d1             	mov    %rdx,%rcx
    5371:	48 29 f1             	sub    %rsi,%rcx
    5374:	0f b6 75 00          	movzbl 0x0(%rbp),%esi
    5378:	44 0f b6 30          	movzbl (%rax),%r14d
    537c:	89 7c 24 5c          	mov    %edi,0x5c(%rsp)
    5380:	44 0f b6 09          	movzbl (%rcx),%r9d
    5384:	48 89 d1             	mov    %rdx,%rcx
    5387:	48 29 f1             	sub    %rsi,%rcx
    538a:	42 8d 44 37 64       	lea    0x64(%rdi,%r14,1),%eax
    538f:	44 89 74 24 60       	mov    %r14d,0x60(%rsp)
    5394:	0f b6 31             	movzbl (%rcx),%esi
    5397:	44 01 c8             	add    %r9d,%eax
    539a:	48 89 d1             	mov    %rdx,%rcx
    539d:	01 f0                	add    %esi,%eax
    539f:	89 74 24 14          	mov    %esi,0x14(%rsp)
    53a3:	0f b6 75 01          	movzbl 0x1(%rbp),%esi
    53a7:	48 29 f1             	sub    %rsi,%rcx
    53aa:	0f b6 75 02          	movzbl 0x2(%rbp),%esi
    53ae:	0f b6 39             	movzbl (%rcx),%edi
    53b1:	48 89 d1             	mov    %rdx,%rcx
    53b4:	48 29 f1             	sub    %rsi,%rcx
    53b7:	0f b6 75 03          	movzbl 0x3(%rbp),%esi
    53bb:	0f b6 09             	movzbl (%rcx),%ecx
    53be:	01 f8                	add    %edi,%eax
    53c0:	89 7c 24 18          	mov    %edi,0x18(%rsp)
    53c4:	01 c8                	add    %ecx,%eax
    53c6:	89 4c 24 1c          	mov    %ecx,0x1c(%rsp)
    53ca:	48 89 d1             	mov    %rdx,%rcx
    53cd:	48 29 f1             	sub    %rsi,%rcx
    53d0:	0f b6 31             	movzbl (%rcx),%esi
    53d3:	48 89 d1             	mov    %rdx,%rcx
    53d6:	01 f0                	add    %esi,%eax
    53d8:	89 74 24 20          	mov    %esi,0x20(%rsp)
    53dc:	0f b6 75 04          	movzbl 0x4(%rbp),%esi
    53e0:	48 29 f1             	sub    %rsi,%rcx
    53e3:	43 0f b6 74 15 fd    	movzbl -0x3(%r13,%r10,1),%esi
    53e9:	44 0f b6 39          	movzbl (%rcx),%r15d
    53ed:	48 89 d1             	mov    %rdx,%rcx
    53f0:	48 29 f1             	sub    %rsi,%rcx
    53f3:	41 0f b6 33          	movzbl (%r11),%esi
    53f7:	44 0f b6 29          	movzbl (%rcx),%r13d
    53fb:	48 89 d1             	mov    %rdx,%rcx
    53fe:	44 01 f8             	add    %r15d,%eax
    5401:	44 89 7c 24 24       	mov    %r15d,0x24(%rsp)
    5406:	48 29 f1             	sub    %rsi,%rcx
    5409:	0f b6 09             	movzbl (%rcx),%ecx
    540c:	44 01 e8             	add    %r13d,%eax
    540f:	44 89 2c 24          	mov    %r13d,(%rsp)
    5413:	89 4c 24 08          	mov    %ecx,0x8(%rsp)
    5417:	41 0f b6 73 01       	movzbl 0x1(%r11),%esi
    541c:	01 c8                	add    %ecx,%eax
    541e:	48 89 d1             	mov    %rdx,%rcx
    5421:	45 0f b6 6b 04       	movzbl 0x4(%r11),%r13d
    5426:	45 0f b6 73 05       	movzbl 0x5(%r11),%r14d
    542b:	48 29 f1             	sub    %rsi,%rcx
    542e:	41 0f b6 73 02       	movzbl 0x2(%r11),%esi
    5433:	0f b6 39             	movzbl (%rcx),%edi
    5436:	48 89 d1             	mov    %rdx,%rcx
    5439:	48 29 f1             	sub    %rsi,%rcx
    543c:	41 0f b6 73 03       	movzbl 0x3(%r11),%esi
    5441:	44 0f b6 39          	movzbl (%rcx),%r15d
    5445:	48 89 d1             	mov    %rdx,%rcx
    5448:	01 f8                	add    %edi,%eax
    544a:	48 29 f1             	sub    %rsi,%rcx
    544d:	0f b6 31             	movzbl (%rcx),%esi
    5450:	48 89 d1             	mov    %rdx,%rcx
    5453:	44 01 f8             	add    %r15d,%eax
    5456:	44 89 7c 24 28       	mov    %r15d,0x28(%rsp)
    545b:	4c 29 e9             	sub    %r13,%rcx
    545e:	49 89 d5             	mov    %rdx,%r13
    5461:	4d 29 f5             	sub    %r14,%r13
    5464:	47 0f b6 74 10 fd    	movzbl -0x3(%r8,%r10,1),%r14d
    546a:	0f b6 09             	movzbl (%rcx),%ecx
    546d:	01 f0                	add    %esi,%eax
    546f:	45 0f b6 7d 00       	movzbl 0x0(%r13),%r15d
    5474:	49 89 d5             	mov    %rdx,%r13
    5477:	4d 29 f5             	sub    %r14,%r13
    547a:	01 c8                	add    %ecx,%eax
    547c:	45 0f b6 34 24       	movzbl (%r12),%r14d
    5481:	45 0f b6 6d 00       	movzbl 0x0(%r13),%r13d
    5486:	44 01 f8             	add    %r15d,%eax
    5489:	44 89 7c 24 2c       	mov    %r15d,0x2c(%rsp)
    548e:	44 01 e8             	add    %r13d,%eax
    5491:	44 89 6c 24 30       	mov    %r13d,0x30(%rsp)
    5496:	49 89 d5             	mov    %rdx,%r13
    5499:	4d 29 f5             	sub    %r14,%r13
    549c:	45 0f b6 74 24 01    	movzbl 0x1(%r12),%r14d
    54a2:	45 0f b6 6d 00       	movzbl 0x0(%r13),%r13d
    54a7:	44 01 e8             	add    %r13d,%eax
    54aa:	44 89 6c 24 34       	mov    %r13d,0x34(%rsp)
    54af:	49 89 d5             	mov    %rdx,%r13
    54b2:	4d 29 f5             	sub    %r14,%r13
    54b5:	45 0f b6 6d 00       	movzbl 0x0(%r13),%r13d
    54ba:	44 01 e8             	add    %r13d,%eax
    54bd:	3b 44 24 10          	cmp    0x10(%rsp),%eax
    54c1:	0f 8d f1 05 00 00    	jge    5ab8 <susan_corners+0x958>
    54c7:	45 0f b6 7c 24 03    	movzbl 0x3(%r12),%r15d
    54cd:	49 89 d6             	mov    %rdx,%r14
    54d0:	4d 29 fe             	sub    %r15,%r14
    54d3:	45 0f b6 36          	movzbl (%r14),%r14d
    54d7:	44 89 74 24 64       	mov    %r14d,0x64(%rsp)
    54dc:	44 01 f0             	add    %r14d,%eax
    54df:	39 44 24 10          	cmp    %eax,0x10(%rsp)
    54e3:	0f 8e cf 05 00 00    	jle    5ab8 <susan_corners+0x958>
    54e9:	45 0f b6 7c 24 04    	movzbl 0x4(%r12),%r15d
    54ef:	49 89 d6             	mov    %rdx,%r14
    54f2:	4d 29 fe             	sub    %r15,%r14
    54f5:	45 0f b6 36          	movzbl (%r14),%r14d
    54f9:	44 89 74 24 70       	mov    %r14d,0x70(%rsp)
    54fe:	44 01 f0             	add    %r14d,%eax
    5501:	39 44 24 10          	cmp    %eax,0x10(%rsp)
    5505:	0f 8e ad 05 00 00    	jle    5ab8 <susan_corners+0x958>
    550b:	45 0f b6 7c 24 05    	movzbl 0x5(%r12),%r15d
    5511:	49 89 d6             	mov    %rdx,%r14
    5514:	4d 29 fe             	sub    %r15,%r14
    5517:	45 0f b6 36          	movzbl (%r14),%r14d
    551b:	44 89 b4 24 b8 00 00 	mov    %r14d,0xb8(%rsp)
    5522:	00 
    5523:	44 01 f0             	add    %r14d,%eax
    5526:	39 44 24 10          	cmp    %eax,0x10(%rsp)
    552a:	0f 8e 88 05 00 00    	jle    5ab8 <susan_corners+0x958>
    5530:	4c 8b b4 24 88 00 00 	mov    0x88(%rsp),%r14
    5537:	00 
    5538:	47 0f b6 7c 16 fd    	movzbl -0x3(%r14,%r10,1),%r15d
    553e:	49 89 d6             	mov    %rdx,%r14
    5541:	4d 29 fe             	sub    %r15,%r14
    5544:	45 0f b6 36          	movzbl (%r14),%r14d
    5548:	44 89 b4 24 bc 00 00 	mov    %r14d,0xbc(%rsp)
    554f:	00 
    5550:	44 01 f0             	add    %r14d,%eax
    5553:	39 44 24 10          	cmp    %eax,0x10(%rsp)
    5557:	0f 8e 5b 05 00 00    	jle    5ab8 <susan_corners+0x958>
    555d:	4c 8b 74 24 40       	mov    0x40(%rsp),%r14
    5562:	45 0f b6 3e          	movzbl (%r14),%r15d
    5566:	49 89 d6             	mov    %rdx,%r14
    5569:	4d 29 fe             	sub    %r15,%r14
    556c:	45 0f b6 36          	movzbl (%r14),%r14d
    5570:	44 89 b4 24 f8 00 00 	mov    %r14d,0xf8(%rsp)
    5577:	00 
    5578:	45 8d 3c 06          	lea    (%r14,%rax,1),%r15d
    557c:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5581:	0f 8e 31 05 00 00    	jle    5ab8 <susan_corners+0x958>
    5587:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    558c:	44 0f b6 70 01       	movzbl 0x1(%rax),%r14d
    5591:	48 89 d0             	mov    %rdx,%rax
    5594:	4c 29 f0             	sub    %r14,%rax
    5597:	0f b6 00             	movzbl (%rax),%eax
    559a:	89 84 24 fc 00 00 00 	mov    %eax,0xfc(%rsp)
    55a1:	41 01 c7             	add    %eax,%r15d
    55a4:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    55a9:	0f 8e 09 05 00 00    	jle    5ab8 <susan_corners+0x958>
    55af:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    55b4:	44 0f b6 70 02       	movzbl 0x2(%rax),%r14d
    55b9:	48 89 d0             	mov    %rdx,%rax
    55bc:	4c 29 f0             	sub    %r14,%rax
    55bf:	0f b6 00             	movzbl (%rax),%eax
    55c2:	89 84 24 00 01 00 00 	mov    %eax,0x100(%rsp)
    55c9:	41 01 c7             	add    %eax,%r15d
    55cc:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    55d1:	0f 8e e1 04 00 00    	jle    5ab8 <susan_corners+0x958>
    55d7:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    55dc:	44 0f b6 70 03       	movzbl 0x3(%rax),%r14d
    55e1:	48 89 d0             	mov    %rdx,%rax
    55e4:	4c 29 f0             	sub    %r14,%rax
    55e7:	0f b6 00             	movzbl (%rax),%eax
    55ea:	89 84 24 04 01 00 00 	mov    %eax,0x104(%rsp)
    55f1:	41 01 c7             	add    %eax,%r15d
    55f4:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    55f9:	0f 8e b9 04 00 00    	jle    5ab8 <susan_corners+0x958>
    55ff:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    5604:	44 0f b6 70 04       	movzbl 0x4(%rax),%r14d
    5609:	48 89 d0             	mov    %rdx,%rax
    560c:	4c 29 f0             	sub    %r14,%rax
    560f:	0f b6 00             	movzbl (%rax),%eax
    5612:	89 84 24 08 01 00 00 	mov    %eax,0x108(%rsp)
    5619:	41 01 c7             	add    %eax,%r15d
    561c:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5621:	0f 8e 91 04 00 00    	jle    5ab8 <susan_corners+0x958>
    5627:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    562c:	44 0f b6 70 05       	movzbl 0x5(%rax),%r14d
    5631:	48 89 d0             	mov    %rdx,%rax
    5634:	4c 29 f0             	sub    %r14,%rax
    5637:	0f b6 00             	movzbl (%rax),%eax
    563a:	89 84 24 0c 01 00 00 	mov    %eax,0x10c(%rsp)
    5641:	41 01 c7             	add    %eax,%r15d
    5644:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5649:	0f 8e 69 04 00 00    	jle    5ab8 <susan_corners+0x958>
    564f:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    5656:	00 
    5657:	46 0f b6 74 10 fe    	movzbl -0x2(%rax,%r10,1),%r14d
    565d:	48 89 d0             	mov    %rdx,%rax
    5660:	4c 29 f0             	sub    %r14,%rax
    5663:	0f b6 00             	movzbl (%rax),%eax
    5666:	89 84 24 10 01 00 00 	mov    %eax,0x110(%rsp)
    566d:	41 01 c7             	add    %eax,%r15d
    5670:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5675:	0f 8e 3d 04 00 00    	jle    5ab8 <susan_corners+0x958>
    567b:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    5682:	00 
    5683:	46 0f b6 74 10 ff    	movzbl -0x1(%rax,%r10,1),%r14d
    5689:	48 89 d0             	mov    %rdx,%rax
    568c:	4c 29 f0             	sub    %r14,%rax
    568f:	0f b6 00             	movzbl (%rax),%eax
    5692:	89 84 24 14 01 00 00 	mov    %eax,0x114(%rsp)
    5699:	41 01 c7             	add    %eax,%r15d
    569c:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    56a1:	0f 8e 11 04 00 00    	jle    5ab8 <susan_corners+0x958>
    56a7:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    56ae:	00 
    56af:	46 0f b6 34 10       	movzbl (%rax,%r10,1),%r14d
    56b4:	48 89 d0             	mov    %rdx,%rax
    56b7:	4c 29 f0             	sub    %r14,%rax
    56ba:	0f b6 00             	movzbl (%rax),%eax
    56bd:	89 84 24 18 01 00 00 	mov    %eax,0x118(%rsp)
    56c4:	41 01 c7             	add    %eax,%r15d
    56c7:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    56cc:	0f 8e e6 03 00 00    	jle    5ab8 <susan_corners+0x958>
    56d2:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    56d9:	00 
    56da:	46 0f b6 74 10 01    	movzbl 0x1(%rax,%r10,1),%r14d
    56e0:	48 89 d0             	mov    %rdx,%rax
    56e3:	4c 29 f0             	sub    %r14,%rax
    56e6:	0f b6 00             	movzbl (%rax),%eax
    56e9:	89 84 24 1c 01 00 00 	mov    %eax,0x11c(%rsp)
    56f0:	41 01 c7             	add    %eax,%r15d
    56f3:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    56f8:	0f 8e ba 03 00 00    	jle    5ab8 <susan_corners+0x958>
    56fe:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    5705:	00 
    5706:	46 0f b6 74 10 02    	movzbl 0x2(%rax,%r10,1),%r14d
    570c:	48 89 d0             	mov    %rdx,%rax
    570f:	4c 29 f0             	sub    %r14,%rax
    5712:	0f b6 00             	movzbl (%rax),%eax
    5715:	89 84 24 20 01 00 00 	mov    %eax,0x120(%rsp)
    571c:	41 01 c7             	add    %eax,%r15d
    571f:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5724:	0f 8e 8e 03 00 00    	jle    5ab8 <susan_corners+0x958>
    572a:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    5731:	00 
    5732:	46 0f b6 74 10 ff    	movzbl -0x1(%rax,%r10,1),%r14d
    5738:	48 89 d0             	mov    %rdx,%rax
    573b:	4c 29 f0             	sub    %r14,%rax
    573e:	0f b6 00             	movzbl (%rax),%eax
    5741:	89 84 24 24 01 00 00 	mov    %eax,0x124(%rsp)
    5748:	41 01 c7             	add    %eax,%r15d
    574b:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    5750:	0f 8e 62 03 00 00    	jle    5ab8 <susan_corners+0x958>
    5756:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    575d:	00 
    575e:	46 0f b6 34 10       	movzbl (%rax,%r10,1),%r14d
    5763:	48 89 d0             	mov    %rdx,%rax
    5766:	4c 29 f0             	sub    %r14,%rax
    5769:	0f b6 00             	movzbl (%rax),%eax
    576c:	89 84 24 28 01 00 00 	mov    %eax,0x128(%rsp)
    5773:	41 01 c7             	add    %eax,%r15d
    5776:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    577b:	0f 8e 37 03 00 00    	jle    5ab8 <susan_corners+0x958>
    5781:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    5788:	00 
    5789:	46 0f b6 74 10 01    	movzbl 0x1(%rax,%r10,1),%r14d
    578f:	48 89 d0             	mov    %rdx,%rax
    5792:	4c 29 f0             	sub    %r14,%rax
    5795:	0f b6 00             	movzbl (%rax),%eax
    5798:	89 84 24 2c 01 00 00 	mov    %eax,0x12c(%rsp)
    579f:	41 01 c7             	add    %eax,%r15d
    57a2:	44 39 7c 24 10       	cmp    %r15d,0x10(%rsp)
    57a7:	0f 8e 0b 03 00 00    	jle    5ab8 <susan_corners+0x958>
    57ad:	44 8b 74 24 60       	mov    0x60(%rsp),%r14d
    57b2:	44 03 74 24 5c       	add    0x5c(%rsp),%r14d
    57b7:	44 89 f0             	mov    %r14d,%eax
    57ba:	44 01 c8             	add    %r9d,%eax
    57bd:	44 2b 4c 24 5c       	sub    0x5c(%rsp),%r9d
    57c2:	44 6b f0 fd          	imul   $0xfffffffd,%eax,%r14d
    57c6:	8b 44 24 14          	mov    0x14(%rsp),%eax
    57ca:	01 c0                	add    %eax,%eax
    57cc:	41 29 c1             	sub    %eax,%r9d
    57cf:	41 29 c6             	sub    %eax,%r14d
    57d2:	8b 44 24 18          	mov    0x18(%rsp),%eax
    57d6:	41 29 c1             	sub    %eax,%r9d
    57d9:	01 c0                	add    %eax,%eax
    57db:	41 29 c6             	sub    %eax,%r14d
    57de:	8b 44 24 1c          	mov    0x1c(%rsp),%eax
    57e2:	01 c0                	add    %eax,%eax
    57e4:	41 29 c6             	sub    %eax,%r14d
    57e7:	8b 44 24 20          	mov    0x20(%rsp),%eax
    57eb:	41 01 c1             	add    %eax,%r9d
    57ee:	01 c0                	add    %eax,%eax
    57f0:	41 29 c6             	sub    %eax,%r14d
    57f3:	8b 44 24 24          	mov    0x24(%rsp),%eax
    57f7:	01 c0                	add    %eax,%eax
    57f9:	41 01 c1             	add    %eax,%r9d
    57fc:	41 29 c6             	sub    %eax,%r14d
    57ff:	44 2b 34 24          	sub    (%rsp),%r14d
    5803:	6b 04 24 fd          	imul   $0xfffffffd,(%rsp),%eax
    5807:	41 01 c1             	add    %eax,%r9d
    580a:	8b 44 24 08          	mov    0x8(%rsp),%eax
    580e:	01 c0                	add    %eax,%eax
    5810:	41 29 c1             	sub    %eax,%r9d
    5813:	44 89 f0             	mov    %r14d,%eax
    5816:	2b 44 24 08          	sub    0x8(%rsp),%eax
    581a:	44 8b 74 24 70       	mov    0x70(%rsp),%r14d
    581f:	41 29 f9             	sub    %edi,%r9d
    5822:	29 f8                	sub    %edi,%eax
    5824:	89 c7                	mov    %eax,%edi
    5826:	42 8d 04 0e          	lea    (%rsi,%r9,1),%eax
    582a:	44 8b 4c 24 2c       	mov    0x2c(%rsp),%r9d
    582f:	2b 7c 24 28          	sub    0x28(%rsp),%edi
    5833:	29 f7                	sub    %esi,%edi
    5835:	8d 34 48             	lea    (%rax,%rcx,2),%esi
    5838:	43 8d 04 49          	lea    (%r9,%r9,2),%eax
    583c:	29 cf                	sub    %ecx,%edi
    583e:	8d 0c 30             	lea    (%rax,%rsi,1),%ecx
    5841:	89 fe                	mov    %edi,%esi
    5843:	8b bc 24 bc 00 00 00 	mov    0xbc(%rsp),%edi
    584a:	6b 44 24 30 fd       	imul   $0xfffffffd,0x30(%rsp),%eax
    584f:	44 29 ce             	sub    %r9d,%esi
    5852:	44 8b 8c 24 18 01 00 	mov    0x118(%rsp),%r9d
    5859:	00 
    585a:	01 c8                	add    %ecx,%eax
    585c:	8b 4c 24 34          	mov    0x34(%rsp),%ecx
    5860:	01 c9                	add    %ecx,%ecx
    5862:	29 c8                	sub    %ecx,%eax
    5864:	6b 8c 24 b8 00 00 00 	imul   $0x3,0xb8(%rsp),%ecx
    586b:	03 
    586c:	44 29 e8             	sub    %r13d,%eax
    586f:	03 44 24 64          	add    0x64(%rsp),%eax
    5873:	42 8d 04 70          	lea    (%rax,%r14,2),%eax
    5877:	01 c1                	add    %eax,%ecx
    5879:	6b c7 fd             	imul   $0xfffffffd,%edi,%eax
    587c:	01 c8                	add    %ecx,%eax
    587e:	8d 0c 37             	lea    (%rdi,%rsi,1),%ecx
    5881:	8b bc 24 f8 00 00 00 	mov    0xf8(%rsp),%edi
    5888:	8d 34 3f             	lea    (%rdi,%rdi,1),%esi
    588b:	01 f9                	add    %edi,%ecx
    588d:	8b bc 24 fc 00 00 00 	mov    0xfc(%rsp),%edi
    5894:	29 f0                	sub    %esi,%eax
    5896:	41 89 c6             	mov    %eax,%r14d
    5899:	89 f8                	mov    %edi,%eax
    589b:	41 29 fe             	sub    %edi,%r14d
    589e:	8b bc 24 04 01 00 00 	mov    0x104(%rsp),%edi
    58a5:	01 c8                	add    %ecx,%eax
    58a7:	03 84 24 00 01 00 00 	add    0x100(%rsp),%eax
    58ae:	42 8d 0c 37          	lea    (%rdi,%r14,1),%ecx
    58b2:	01 f8                	add    %edi,%eax
    58b4:	8b bc 24 08 01 00 00 	mov    0x108(%rsp),%edi
    58bb:	8d 34 79             	lea    (%rcx,%rdi,2),%esi
    58be:	01 f8                	add    %edi,%eax
    58c0:	8b bc 24 0c 01 00 00 	mov    0x10c(%rsp),%edi
    58c7:	8d 0c 7f             	lea    (%rdi,%rdi,2),%ecx
    58ca:	01 f8                	add    %edi,%eax
    58cc:	01 f1                	add    %esi,%ecx
    58ce:	8b b4 24 10 01 00 00 	mov    0x110(%rsp),%esi
    58d5:	01 f6                	add    %esi,%esi
    58d7:	29 f1                	sub    %esi,%ecx
    58d9:	01 c6                	add    %eax,%esi
    58db:	8b 84 24 14 01 00 00 	mov    0x114(%rsp),%eax
    58e2:	29 c1                	sub    %eax,%ecx
    58e4:	8d 04 46             	lea    (%rsi,%rax,2),%eax
    58e7:	8b b4 24 1c 01 00 00 	mov    0x11c(%rsp),%esi
    58ee:	89 cf                	mov    %ecx,%edi
    58f0:	42 8d 0c 48          	lea    (%rax,%r9,2),%ecx
    58f4:	8d 04 3e             	lea    (%rsi,%rdi,1),%eax
    58f7:	8d 34 71             	lea    (%rcx,%rsi,2),%esi
    58fa:	8b 8c 24 20 01 00 00 	mov    0x120(%rsp),%ecx
    5901:	8b bc 24 24 01 00 00 	mov    0x124(%rsp),%edi
    5908:	01 c9                	add    %ecx,%ecx
    590a:	01 c8                	add    %ecx,%eax
    590c:	01 f1                	add    %esi,%ecx
    590e:	89 c6                	mov    %eax,%esi
    5910:	8d 04 7f             	lea    (%rdi,%rdi,2),%eax
    5913:	01 c1                	add    %eax,%ecx
    5915:	6b 84 24 28 01 00 00 	imul   $0x3,0x128(%rsp),%eax
    591c:	03 
    591d:	29 fe                	sub    %edi,%esi
    591f:	8b bc 24 2c 01 00 00 	mov    0x12c(%rsp),%edi
    5926:	44 8d 34 37          	lea    (%rdi,%rsi,1),%r14d
    592a:	01 c8                	add    %ecx,%eax
    592c:	8d 0c 7f             	lea    (%rdi,%rdi,2),%ecx
    592f:	44 89 f6             	mov    %r14d,%esi
    5932:	41 0f af f6          	imul   %r14d,%esi
    5936:	44 8d 0c 01          	lea    (%rcx,%rax,1),%r9d
    593a:	44 89 f8             	mov    %r15d,%eax
    593d:	44 89 c9             	mov    %r9d,%ecx
    5940:	41 0f af c7          	imul   %r15d,%eax
    5944:	41 0f af c9          	imul   %r9d,%ecx
    5948:	d1 f8                	sar    %eax
    594a:	8d 3c 0e             	lea    (%rsi,%rcx,1),%edi
    594d:	39 f8                	cmp    %edi,%eax
    594f:	0f 8d 63 01 00 00    	jge    5ab8 <susan_corners+0x958>
    5955:	39 ce                	cmp    %ecx,%esi
    5957:	0f 8e ed 05 00 00    	jle    5f4a <susan_corners+0xdea>
    595d:	44 89 f0             	mov    %r14d,%eax
    5960:	66 0f ef c0          	pxor   %xmm0,%xmm0
    5964:	66 0f ef c9          	pxor   %xmm1,%xmm1
    5968:	44 89 f6             	mov    %r14d,%esi
    596b:	f7 d8                	neg    %eax
    596d:	f3 41 0f 2a c1       	cvtsi2ss %r9d,%xmm0
    5972:	66 0f ef db          	pxor   %xmm3,%xmm3
    5976:	41 0f 48 c6          	cmovs  %r14d,%eax
    597a:	c1 fe 1f             	sar    $0x1f,%esi
    597d:	83 ce 01             	or     $0x1,%esi
    5980:	f3 0f 2a c8          	cvtsi2ss %eax,%xmm1
    5984:	48 8b 05 1d 1d 00 00 	mov    0x1d1d(%rip),%rax        # 76a8 <_IO_stdin_used+0x6a8>
    598b:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    598f:	66 48 0f 6e c8       	movq   %rax,%xmm1
    5994:	0f 2f d0             	comiss %xmm0,%xmm2
    5997:	f3 0f 5a d8          	cvtss2sd %xmm0,%xmm3
    599b:	0f 87 9c 05 00 00    	ja     5f3d <susan_corners+0xddd>
    59a1:	f2 0f 58 d9          	addsd  %xmm1,%xmm3
    59a5:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    59a9:	03 84 24 90 00 00 00 	add    0x90(%rsp),%eax
    59b0:	48 8b 7c 24 78       	mov    0x78(%rsp),%rdi
    59b5:	0f 28 e8             	movaps %xmm0,%xmm5
    59b8:	66 0f ef db          	pxor   %xmm3,%xmm3
    59bc:	0f af 84 24 f4 00 00 	imul   0xf4(%rsp),%eax
    59c3:	00 
    59c4:	03 44 24 58          	add    0x58(%rsp),%eax
    59c8:	f3 0f 58 e8          	addss  %xmm0,%xmm5
    59cc:	01 f0                	add    %esi,%eax
    59ce:	48 98                	cltq   
    59d0:	0f b6 0c 07          	movzbl (%rdi,%rax,1),%ecx
    59d4:	48 89 d0             	mov    %rdx,%rax
    59d7:	f3 0f 5a dd          	cvtss2sd %xmm5,%xmm3
    59db:	48 29 c8             	sub    %rcx,%rax
    59de:	0f 2f d5             	comiss %xmm5,%xmm2
    59e1:	0f b6 38             	movzbl (%rax),%edi
    59e4:	0f 87 46 05 00 00    	ja     5f30 <susan_corners+0xdd0>
    59ea:	f2 0f 58 d9          	addsd  %xmm1,%xmm3
    59ee:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    59f2:	03 84 24 90 00 00 00 	add    0x90(%rsp),%eax
    59f9:	0f af 84 24 f4 00 00 	imul   0xf4(%rsp),%eax
    5a00:	00 
    5a01:	66 0f ef db          	pxor   %xmm3,%xmm3
    5a05:	03 44 24 58          	add    0x58(%rsp),%eax
    5a09:	48 8b 4c 24 78       	mov    0x78(%rsp),%rcx
    5a0e:	8d 04 70             	lea    (%rax,%rsi,2),%eax
    5a11:	f3 0f 59 05 ab 1c 00 	mulss  0x1cab(%rip),%xmm0        # 76c4 <_IO_stdin_used+0x6c4>
    5a18:	00 
    5a19:	48 98                	cltq   
    5a1b:	0f b6 0c 01          	movzbl (%rcx,%rax,1),%ecx
    5a1f:	48 89 d0             	mov    %rdx,%rax
    5a22:	48 29 c8             	sub    %rcx,%rax
    5a25:	0f b6 00             	movzbl (%rax),%eax
    5a28:	f3 0f 5a d8          	cvtss2sd %xmm0,%xmm3
    5a2c:	01 c7                	add    %eax,%edi
    5a2e:	0f 2f d0             	comiss %xmm0,%xmm2
    5a31:	0f 87 ec 04 00 00    	ja     5f23 <susan_corners+0xdc3>
    5a37:	f2 0f 58 cb          	addsd  %xmm3,%xmm1
    5a3b:	f2 0f 2c c1          	cvttsd2si %xmm1,%eax
    5a3f:	8d 0c 76             	lea    (%rsi,%rsi,2),%ecx
    5a42:	03 84 24 90 00 00 00 	add    0x90(%rsp),%eax
    5a49:	48 8b 74 24 78       	mov    0x78(%rsp),%rsi
    5a4e:	0f af 84 24 f4 00 00 	imul   0xf4(%rsp),%eax
    5a55:	00 
    5a56:	03 44 24 58          	add    0x58(%rsp),%eax
    5a5a:	01 c8                	add    %ecx,%eax
    5a5c:	48 98                	cltq   
    5a5e:	0f b6 04 06          	movzbl (%rsi,%rax,1),%eax
    5a62:	48 29 c2             	sub    %rax,%rdx
    5a65:	0f b6 02             	movzbl (%rdx),%eax
    5a68:	01 f8                	add    %edi,%eax
    5a6a:	3d 22 01 00 00       	cmp    $0x122,%eax
    5a6f:	7e 47                	jle    5ab8 <susan_corners+0x958>
    5a71:	8b 44 24 10          	mov    0x10(%rsp),%eax
    5a75:	48 8b bc 24 d8 00 00 	mov    0xd8(%rsp),%rdi
    5a7c:	00 
    5a7d:	48 8b 8c 24 80 00 00 	mov    0x80(%rsp),%rcx
    5a84:	00 
    5a85:	48 03 8c 24 a0 00 00 	add    0xa0(%rsp),%rcx
    5a8c:	00 
    5a8d:	44 29 f8             	sub    %r15d,%eax
    5a90:	42 89 04 97          	mov    %eax,(%rdi,%r10,4)
    5a94:	41 6b c6 33          	imul   $0x33,%r14d,%eax
    5a98:	48 8b bc 24 e0 00 00 	mov    0xe0(%rsp),%rdi
    5a9f:	00 
    5aa0:	99                   	cltd   
    5aa1:	41 f7 ff             	idiv   %r15d
    5aa4:	42 89 04 97          	mov    %eax,(%rdi,%r10,4)
    5aa8:	41 6b c1 33          	imul   $0x33,%r9d,%eax
    5aac:	99                   	cltd   
    5aad:	41 f7 ff             	idiv   %r15d
    5ab0:	42 89 04 91          	mov    %eax,(%rcx,%r10,4)
    5ab4:	0f 1f 40 00          	nopl   0x0(%rax)
    5ab8:	49 83 c2 01          	add    $0x1,%r10
    5abc:	48 83 c3 01          	add    $0x1,%rbx
    5ac0:	48 83 c5 01          	add    $0x1,%rbp
    5ac4:	49 83 c3 01          	add    $0x1,%r11
    5ac8:	48 83 44 24 40 01    	addq   $0x1,0x40(%rsp)
    5ace:	49 83 c4 01          	add    $0x1,%r12
    5ad2:	4c 39 54 24 48       	cmp    %r10,0x48(%rsp)
    5ad7:	0f 85 63 f8 ff ff    	jne    5340 <susan_corners+0x1e0>
    5add:	48 8b 9c 24 a8 00 00 	mov    0xa8(%rsp),%rbx
    5ae4:	00 
    5ae5:	83 84 24 90 00 00 00 	addl   $0x1,0x90(%rsp)
    5aec:	01 
    5aed:	48 8b bc 24 c8 00 00 	mov    0xc8(%rsp),%rdi
    5af4:	00 
    5af5:	48 01 5c 24 38       	add    %rbx,0x38(%rsp)
    5afa:	48 01 9c 24 b0 00 00 	add    %rbx,0xb0(%rsp)
    5b01:	00 
    5b02:	8b 84 24 90 00 00 00 	mov    0x90(%rsp),%eax
    5b09:	48 01 9c 24 98 00 00 	add    %rbx,0x98(%rsp)
    5b10:	00 
    5b11:	4c 8b ac 24 88 00 00 	mov    0x88(%rsp),%r13
    5b18:	00 
    5b19:	48 01 bc 24 a0 00 00 	add    %rdi,0xa0(%rsp)
    5b20:	00 
    5b21:	3b 44 24 74          	cmp    0x74(%rsp),%eax
    5b25:	0f 85 85 f7 ff ff    	jne    52b0 <susan_corners+0x150>
    5b2b:	4c 8b ac 24 c0 00 00 	mov    0xc0(%rsp),%r13
    5b32:	00 
    5b33:	44 8b 9c 24 f4 00 00 	mov    0xf4(%rsp),%r11d
    5b3a:	00 
    5b3b:	c7 44 24 14 00 00 00 	movl   $0x0,0x14(%rsp)
    5b42:	00 
    5b43:	b8 05 00 00 00       	mov    $0x5,%eax
    5b48:	66 0f 6e c0          	movd   %eax,%xmm0
    5b4c:	47 8d 14 9b          	lea    (%r11,%r11,4),%r10d
    5b50:	45 8d 4b f5          	lea    -0xb(%r11),%r9d
    5b54:	47 8d 34 1b          	lea    (%r11,%r11,1),%r14d
    5b58:	49 83 c1 06          	add    $0x6,%r9
    5b5c:	49 63 d2             	movslq %r10d,%rdx
    5b5f:	90                   	nop
    5b60:	83 bc 24 94 00 00 00 	cmpl   $0x5,0x94(%rsp)
    5b67:	05 
    5b68:	43 8d 1c 33          	lea    (%r11,%r14,1),%ebx
    5b6c:	42 8d 2c 1a          	lea    (%rdx,%r11,1),%ebp
    5b70:	0f 8e 3b 03 00 00    	jle    5eb1 <susan_corners+0xd51>
    5b76:	42 8d 2c 1a          	lea    (%rdx,%r11,1),%ebp
    5b7a:	48 8b 7c 24 68       	mov    0x68(%rsp),%rdi
    5b7f:	46 8d 3c 1b          	lea    (%rbx,%r11,1),%r15d
    5b83:	46 8d 64 1d 00       	lea    0x0(%rbp,%r11,1),%r12d
    5b88:	43 8d 04 1c          	lea    (%r12,%r11,1),%eax
    5b8c:	89 44 24 10          	mov    %eax,0x10(%rsp)
    5b90:	48 8d 04 95 00 00 00 	lea    0x0(,%rdx,4),%rax
    5b97:	00 
    5b98:	48 03 54 24 78       	add    0x78(%rsp),%rdx
    5b9d:	48 89 54 24 08       	mov    %rdx,0x8(%rsp)
    5ba2:	49 8d 4c 05 00       	lea    0x0(%r13,%rax,1),%rcx
    5ba7:	4c 8d 14 07          	lea    (%rdi,%rax,1),%r10
    5bab:	48 03 84 24 80 00 00 	add    0x80(%rsp),%rax
    5bb2:	00 
    5bb3:	48 89 04 24          	mov    %rax,(%rsp)
    5bb7:	b8 05 00 00 00       	mov    $0x5,%eax
    5bbc:	0f 1f 40 00          	nopl   0x0(%rax)
    5bc0:	8b 51 14             	mov    0x14(%rcx),%edx
    5bc3:	66 0f 6e c8          	movd   %eax,%xmm1
    5bc7:	66 0f 62 c8          	punpckldq %xmm0,%xmm1
    5bcb:	85 d2                	test   %edx,%edx
    5bcd:	0f 8e cd 02 00 00    	jle    5ea0 <susan_corners+0xd40>
    5bd3:	41 8d 34 06          	lea    (%r14,%rax,1),%esi
    5bd7:	48 63 f6             	movslq %esi,%rsi
    5bda:	4c 8d 04 b5 00 00 00 	lea    0x0(,%rsi,4),%r8
    5be1:	00 
    5be2:	41 39 54 b5 f4       	cmp    %edx,-0xc(%r13,%rsi,4)
    5be7:	0f 8d b3 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5bed:	43 39 54 05 f8       	cmp    %edx,-0x8(%r13,%r8,1)
    5bf2:	0f 8d a8 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5bf8:	43 39 54 05 fc       	cmp    %edx,-0x4(%r13,%r8,1)
    5bfd:	0f 8d 9d 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c03:	41 39 54 b5 00       	cmp    %edx,0x0(%r13,%rsi,4)
    5c08:	0f 8d 92 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c0e:	43 39 54 05 04       	cmp    %edx,0x4(%r13,%r8,1)
    5c13:	0f 8d 87 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c19:	43 39 54 05 08       	cmp    %edx,0x8(%r13,%r8,1)
    5c1e:	0f 8d 7c 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c24:	43 39 54 05 0c       	cmp    %edx,0xc(%r13,%r8,1)
    5c29:	0f 8d 71 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c2f:	8d 34 03             	lea    (%rbx,%rax,1),%esi
    5c32:	48 63 f6             	movslq %esi,%rsi
    5c35:	4c 8d 04 b5 00 00 00 	lea    0x0(,%rsi,4),%r8
    5c3c:	00 
    5c3d:	41 39 54 b5 f4       	cmp    %edx,-0xc(%r13,%rsi,4)
    5c42:	0f 8d 58 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c48:	43 39 54 05 f8       	cmp    %edx,-0x8(%r13,%r8,1)
    5c4d:	0f 8d 4d 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c53:	43 39 54 05 fc       	cmp    %edx,-0x4(%r13,%r8,1)
    5c58:	0f 8d 42 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c5e:	41 39 54 b5 00       	cmp    %edx,0x0(%r13,%rsi,4)
    5c63:	0f 8d 37 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c69:	43 39 54 05 04       	cmp    %edx,0x4(%r13,%r8,1)
    5c6e:	0f 8d 2c 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c74:	43 39 54 05 08       	cmp    %edx,0x8(%r13,%r8,1)
    5c79:	0f 8d 21 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c7f:	43 39 54 05 0c       	cmp    %edx,0xc(%r13,%r8,1)
    5c84:	0f 8d 16 02 00 00    	jge    5ea0 <susan_corners+0xd40>
    5c8a:	45 8d 04 07          	lea    (%r15,%rax,1),%r8d
    5c8e:	4d 63 c0             	movslq %r8d,%r8
    5c91:	4a 8d 34 85 00 00 00 	lea    0x0(,%r8,4),%rsi
    5c98:	00 
    5c99:	43 39 54 85 f4       	cmp    %edx,-0xc(%r13,%r8,4)
    5c9e:	0f 8d fc 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5ca4:	41 39 54 35 f8       	cmp    %edx,-0x8(%r13,%rsi,1)
    5ca9:	0f 8d f1 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5caf:	41 39 54 35 fc       	cmp    %edx,-0x4(%r13,%rsi,1)
    5cb4:	0f 8d e6 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cba:	43 39 54 85 00       	cmp    %edx,0x0(%r13,%r8,4)
    5cbf:	0f 8d db 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cc5:	41 39 54 35 04       	cmp    %edx,0x4(%r13,%rsi,1)
    5cca:	0f 8d d0 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cd0:	41 39 54 35 08       	cmp    %edx,0x8(%r13,%rsi,1)
    5cd5:	0f 8d c5 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cdb:	41 39 54 35 0c       	cmp    %edx,0xc(%r13,%rsi,1)
    5ce0:	0f 8d ba 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5ce6:	39 51 08             	cmp    %edx,0x8(%rcx)
    5ce9:	0f 8d b1 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cef:	39 51 0c             	cmp    %edx,0xc(%rcx)
    5cf2:	0f 8d a8 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5cf8:	39 51 10             	cmp    %edx,0x10(%rcx)
    5cfb:	0f 8d 9f 01 00 00    	jge    5ea0 <susan_corners+0xd40>
    5d01:	39 51 18             	cmp    %edx,0x18(%rcx)
    5d04:	0f 8f 96 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d0a:	39 51 1c             	cmp    %edx,0x1c(%rcx)
    5d0d:	0f 8f 8d 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d13:	39 51 20             	cmp    %edx,0x20(%rcx)
    5d16:	0f 8f 84 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d1c:	44 8d 44 05 00       	lea    0x0(%rbp,%rax,1),%r8d
    5d21:	4d 63 c0             	movslq %r8d,%r8
    5d24:	4a 8d 34 85 00 00 00 	lea    0x0(,%r8,4),%rsi
    5d2b:	00 
    5d2c:	43 39 54 85 f4       	cmp    %edx,-0xc(%r13,%r8,4)
    5d31:	0f 8f 69 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d37:	41 39 54 35 f8       	cmp    %edx,-0x8(%r13,%rsi,1)
    5d3c:	0f 8f 5e 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d42:	41 39 54 35 fc       	cmp    %edx,-0x4(%r13,%rsi,1)
    5d47:	0f 8f 53 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d4d:	43 39 54 85 00       	cmp    %edx,0x0(%r13,%r8,4)
    5d52:	0f 8f 48 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d58:	41 39 54 35 04       	cmp    %edx,0x4(%r13,%rsi,1)
    5d5d:	0f 8f 3d 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d63:	41 39 54 35 08       	cmp    %edx,0x8(%r13,%rsi,1)
    5d68:	0f 8f 32 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d6e:	41 39 54 35 0c       	cmp    %edx,0xc(%r13,%rsi,1)
    5d73:	0f 8f 27 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d79:	45 8d 04 04          	lea    (%r12,%rax,1),%r8d
    5d7d:	4d 63 c0             	movslq %r8d,%r8
    5d80:	4a 8d 34 85 00 00 00 	lea    0x0(,%r8,4),%rsi
    5d87:	00 
    5d88:	43 39 54 85 f4       	cmp    %edx,-0xc(%r13,%r8,4)
    5d8d:	0f 8f 0d 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d93:	41 39 54 35 f8       	cmp    %edx,-0x8(%r13,%rsi,1)
    5d98:	0f 8f 02 01 00 00    	jg     5ea0 <susan_corners+0xd40>
    5d9e:	41 39 54 35 fc       	cmp    %edx,-0x4(%r13,%rsi,1)
    5da3:	0f 8f f7 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5da9:	43 39 54 85 00       	cmp    %edx,0x0(%r13,%r8,4)
    5dae:	0f 8f ec 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5db4:	41 39 54 35 04       	cmp    %edx,0x4(%r13,%rsi,1)
    5db9:	0f 8f e1 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5dbf:	41 39 54 35 08       	cmp    %edx,0x8(%r13,%rsi,1)
    5dc4:	0f 8f d6 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5dca:	41 39 54 35 0c       	cmp    %edx,0xc(%r13,%rsi,1)
    5dcf:	0f 8f cb 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5dd5:	8b 74 24 10          	mov    0x10(%rsp),%esi
    5dd9:	01 c6                	add    %eax,%esi
    5ddb:	48 63 f6             	movslq %esi,%rsi
    5dde:	48 8d 3c b5 00 00 00 	lea    0x0(,%rsi,4),%rdi
    5de5:	00 
    5de6:	41 39 54 b5 f4       	cmp    %edx,-0xc(%r13,%rsi,4)
    5deb:	0f 8f af 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5df1:	41 39 54 3d f8       	cmp    %edx,-0x8(%r13,%rdi,1)
    5df6:	0f 8f a4 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5dfc:	41 39 54 3d fc       	cmp    %edx,-0x4(%r13,%rdi,1)
    5e01:	0f 8f 99 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5e07:	41 39 54 b5 00       	cmp    %edx,0x0(%r13,%rsi,4)
    5e0c:	0f 8f 8e 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5e12:	41 39 54 3d 04       	cmp    %edx,0x4(%r13,%rdi,1)
    5e17:	0f 8f 83 00 00 00    	jg     5ea0 <susan_corners+0xd40>
    5e1d:	41 39 54 3d 08       	cmp    %edx,0x8(%r13,%rdi,1)
    5e22:	7f 7c                	jg     5ea0 <susan_corners+0xd40>
    5e24:	41 39 54 3d 0c       	cmp    %edx,0xc(%r13,%rdi,1)
    5e29:	7f 75                	jg     5ea0 <susan_corners+0xd40>
    5e2b:	48 63 54 24 14       	movslq 0x14(%rsp),%rdx
    5e30:	41 8b 34 82          	mov    (%r10,%rax,4),%esi
    5e34:	48 89 d7             	mov    %rdx,%rdi
    5e37:	48 6b d2 18          	imul   $0x18,%rdx,%rdx
    5e3b:	48 03 94 24 e8 00 00 	add    0xe8(%rsp),%rdx
    5e42:	00 
    5e43:	89 72 0c             	mov    %esi,0xc(%rdx)
    5e46:	48 8b 34 24          	mov    (%rsp),%rsi
    5e4a:	83 c7 01             	add    $0x1,%edi
    5e4d:	c7 42 08 00 00 00 00 	movl   $0x0,0x8(%rdx)
    5e54:	8b 34 86             	mov    (%rsi,%rax,4),%esi
    5e57:	66 0f d6 0a          	movq   %xmm1,(%rdx)
    5e5b:	89 7c 24 14          	mov    %edi,0x14(%rsp)
    5e5f:	89 72 10             	mov    %esi,0x10(%rdx)
    5e62:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
    5e67:	0f b6 34 06          	movzbl (%rsi,%rax,1),%esi
    5e6b:	89 72 14             	mov    %esi,0x14(%rdx)
    5e6e:	81 ff 98 3a 00 00    	cmp    $0x3a98,%edi
    5e74:	75 2a                	jne    5ea0 <susan_corners+0xd40>
    5e76:	48 8b 0d a3 31 00 00 	mov    0x31a3(%rip),%rcx        # 9020 <stderr@GLIBC_2.2.5>
    5e7d:	ba 12 00 00 00       	mov    $0x12,%edx
    5e82:	be 01 00 00 00       	mov    $0x1,%esi
    5e87:	48 8d 3d 93 16 00 00 	lea    0x1693(%rip),%rdi        # 7521 <_IO_stdin_used+0x521>
    5e8e:	e8 ed b3 ff ff       	call   1280 <fwrite@plt>
    5e93:	bf 01 00 00 00       	mov    $0x1,%edi
    5e98:	e8 d3 b3 ff ff       	call   1270 <exit@plt>
    5e9d:	0f 1f 00             	nopl   (%rax)
    5ea0:	48 83 c0 01          	add    $0x1,%rax
    5ea4:	48 83 c1 04          	add    $0x4,%rcx
    5ea8:	4c 39 c8             	cmp    %r9,%rax
    5eab:	0f 85 0f fd ff ff    	jne    5bc0 <susan_corners+0xa60>
    5eb1:	66 0f 7e c0          	movd   %xmm0,%eax
    5eb5:	48 63 d5             	movslq %ebp,%rdx
    5eb8:	41 89 de             	mov    %ebx,%r14d
    5ebb:	83 c0 01             	add    $0x1,%eax
    5ebe:	66 0f 6e c0          	movd   %eax,%xmm0
    5ec2:	3b 44 24 74          	cmp    0x74(%rsp),%eax
    5ec6:	0f 85 94 fc ff ff    	jne    5b60 <susan_corners+0xa00>
    5ecc:	48 63 44 24 14       	movslq 0x14(%rsp),%rax
    5ed1:	48 8b 9c 24 e8 00 00 	mov    0xe8(%rsp),%rbx
    5ed8:	00 
    5ed9:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
    5edd:	48 8d 04 c3          	lea    (%rbx,%rax,8),%rax
    5ee1:	48 89 84 24 e8 00 00 	mov    %rax,0xe8(%rsp)
    5ee8:	00 
    5ee9:	c7 40 08 07 00 00 00 	movl   $0x7,0x8(%rax)
    5ef0:	48 8b 7c 24 68       	mov    0x68(%rsp),%rdi
    5ef5:	e8 86 b2 ff ff       	call   1180 <free@plt>
    5efa:	48 8b bc 24 80 00 00 	mov    0x80(%rsp),%rdi
    5f01:	00 
    5f02:	e8 79 b2 ff ff       	call   1180 <free@plt>
    5f07:	48 81 c4 38 01 00 00 	add    $0x138,%rsp
    5f0e:	5b                   	pop    %rbx
    5f0f:	5d                   	pop    %rbp
    5f10:	41 5c                	pop    %r12
    5f12:	41 5d                	pop    %r13
    5f14:	41 5e                	pop    %r14
    5f16:	41 5f                	pop    %r15
    5f18:	c3                   	ret    
    5f19:	48 8b 84 24 e8 00 00 	mov    0xe8(%rsp),%rax
    5f20:	00 
    5f21:	eb c6                	jmp    5ee9 <susan_corners+0xd89>
    5f23:	f2 0f 5c d9          	subsd  %xmm1,%xmm3
    5f27:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    5f2b:	e9 0f fb ff ff       	jmp    5a3f <susan_corners+0x8df>
    5f30:	f2 0f 5c d9          	subsd  %xmm1,%xmm3
    5f34:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    5f38:	e9 b5 fa ff ff       	jmp    59f2 <susan_corners+0x892>
    5f3d:	f2 0f 5c d9          	subsd  %xmm1,%xmm3
    5f41:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    5f45:	e9 5f fa ff ff       	jmp    59a9 <susan_corners+0x849>
    5f4a:	44 89 c8             	mov    %r9d,%eax
    5f4d:	66 0f ef c0          	pxor   %xmm0,%xmm0
    5f51:	66 0f ef c9          	pxor   %xmm1,%xmm1
    5f55:	44 89 ce             	mov    %r9d,%esi
    5f58:	f7 d8                	neg    %eax
    5f5a:	f3 41 0f 2a c6       	cvtsi2ss %r14d,%xmm0
    5f5f:	66 0f ef db          	pxor   %xmm3,%xmm3
    5f63:	44 89 d1             	mov    %r10d,%ecx
    5f66:	41 0f 48 c1          	cmovs  %r9d,%eax
    5f6a:	c1 fe 1f             	sar    $0x1f,%esi
    5f6d:	83 ce 01             	or     $0x1,%esi
    5f70:	f3 0f 2a c8          	cvtsi2ss %eax,%xmm1
    5f74:	8b 84 24 90 00 00 00 	mov    0x90(%rsp),%eax
    5f7b:	8d 3c 06             	lea    (%rsi,%rax,1),%edi
    5f7e:	8b 84 24 f4 00 00 00 	mov    0xf4(%rsp),%eax
    5f85:	f3 0f 5e c1          	divss  %xmm1,%xmm0
    5f89:	0f af c7             	imul   %edi,%eax
    5f8c:	66 0f 28 cc          	movapd %xmm4,%xmm1
    5f90:	01 c1                	add    %eax,%ecx
    5f92:	0f 2f d0             	comiss %xmm0,%xmm2
    5f95:	f3 0f 5a d8          	cvtss2sd %xmm0,%xmm3
    5f99:	0f 87 b1 00 00 00    	ja     6050 <susan_corners+0xef0>
    5f9f:	f2 0f 58 dc          	addsd  %xmm4,%xmm3
    5fa3:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    5fa7:	01 c8                	add    %ecx,%eax
    5fa9:	48 8b 4c 24 78       	mov    0x78(%rsp),%rcx
    5fae:	01 f7                	add    %esi,%edi
    5fb0:	0f 28 e8             	movaps %xmm0,%xmm5
    5fb3:	48 98                	cltq   
    5fb5:	f3 0f 58 e8          	addss  %xmm0,%xmm5
    5fb9:	66 0f ef db          	pxor   %xmm3,%xmm3
    5fbd:	0f b6 0c 01          	movzbl (%rcx,%rax,1),%ecx
    5fc1:	48 89 d0             	mov    %rdx,%rax
    5fc4:	48 29 c8             	sub    %rcx,%rax
    5fc7:	44 89 d1             	mov    %r10d,%ecx
    5fca:	f3 0f 5a dd          	cvtss2sd %xmm5,%xmm3
    5fce:	44 0f b6 28          	movzbl (%rax),%r13d
    5fd2:	8b 84 24 f4 00 00 00 	mov    0xf4(%rsp),%eax
    5fd9:	0f af c7             	imul   %edi,%eax
    5fdc:	01 c1                	add    %eax,%ecx
    5fde:	0f 2f d5             	comiss %xmm5,%xmm2
    5fe1:	0f 87 80 00 00 00    	ja     6067 <susan_corners+0xf07>
    5fe7:	f2 0f 58 d9          	addsd  %xmm1,%xmm3
    5feb:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    5fef:	f3 0f 59 05 cd 16 00 	mulss  0x16cd(%rip),%xmm0        # 76c4 <_IO_stdin_used+0x6c4>
    5ff6:	00 
    5ff7:	01 c8                	add    %ecx,%eax
    5ff9:	48 8b 4c 24 78       	mov    0x78(%rsp),%rcx
    5ffe:	66 0f ef db          	pxor   %xmm3,%xmm3
    6002:	48 98                	cltq   
    6004:	0f b6 0c 01          	movzbl (%rcx,%rax,1),%ecx
    6008:	48 89 d0             	mov    %rdx,%rax
    600b:	48 29 c8             	sub    %rcx,%rax
    600e:	44 89 d1             	mov    %r10d,%ecx
    6011:	0f b6 00             	movzbl (%rax),%eax
    6014:	f3 0f 5a d8          	cvtss2sd %xmm0,%xmm3
    6018:	41 01 c5             	add    %eax,%r13d
    601b:	8d 04 37             	lea    (%rdi,%rsi,1),%eax
    601e:	0f af 84 24 f4 00 00 	imul   0xf4(%rsp),%eax
    6025:	00 
    6026:	01 c1                	add    %eax,%ecx
    6028:	0f 2f d0             	comiss %xmm0,%xmm2
    602b:	77 30                	ja     605d <susan_corners+0xefd>
    602d:	f2 0f 58 cb          	addsd  %xmm3,%xmm1
    6031:	f2 0f 2c c1          	cvttsd2si %xmm1,%eax
    6035:	48 8b 7c 24 78       	mov    0x78(%rsp),%rdi
    603a:	01 c8                	add    %ecx,%eax
    603c:	48 98                	cltq   
    603e:	0f b6 04 07          	movzbl (%rdi,%rax,1),%eax
    6042:	48 29 c2             	sub    %rax,%rdx
    6045:	0f b6 02             	movzbl (%rdx),%eax
    6048:	44 01 e8             	add    %r13d,%eax
    604b:	e9 1a fa ff ff       	jmp    5a6a <susan_corners+0x90a>
    6050:	f2 0f 5c dc          	subsd  %xmm4,%xmm3
    6054:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    6058:	e9 4a ff ff ff       	jmp    5fa7 <susan_corners+0xe47>
    605d:	f2 0f 5c d9          	subsd  %xmm1,%xmm3
    6061:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    6065:	eb ce                	jmp    6035 <susan_corners+0xed5>
    6067:	f2 0f 5c d9          	subsd  %xmm1,%xmm3
    606b:	f2 0f 2c c3          	cvttsd2si %xmm3,%eax
    606f:	e9 7b ff ff ff       	jmp    5fef <susan_corners+0xe8f>
    6074:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    607b:	00 00 00 00 
    607f:	90                   	nop

0000000000006080 <susan_corners_quick>:
    6080:	f3 0f 1e fa          	endbr64 
    6084:	41 57                	push   %r15
    6086:	41 56                	push   %r14
    6088:	41 55                	push   %r13
    608a:	49 89 d5             	mov    %rdx,%r13
    608d:	44 89 ca             	mov    %r9d,%edx
    6090:	41 54                	push   %r12
    6092:	49 89 f4             	mov    %rsi,%r12
    6095:	31 f6                	xor    %esi,%esi
    6097:	55                   	push   %rbp
    6098:	53                   	push   %rbx
    6099:	89 cb                	mov    %ecx,%ebx
    609b:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
    60a2:	8b ac 24 10 01 00 00 	mov    0x110(%rsp),%ebp
    60a9:	48 89 7c 24 48       	mov    %rdi,0x48(%rsp)
    60ae:	4c 89 e7             	mov    %r12,%rdi
    60b1:	4c 89 44 24 40       	mov    %r8,0x40(%rsp)
    60b6:	0f af d5             	imul   %ebp,%edx
    60b9:	44 89 4c 24 50       	mov    %r9d,0x50(%rsp)
    60be:	48 63 d2             	movslq %edx,%rdx
    60c1:	48 c1 e2 02          	shl    $0x2,%rdx
    60c5:	e8 16 b1 ff ff       	call   11e0 <memset@plt>
    60ca:	8d 45 f9             	lea    -0x7(%rbp),%eax
    60cd:	89 44 24 04          	mov    %eax,0x4(%rsp)
    60d1:	83 f8 07             	cmp    $0x7,%eax
    60d4:	0f 8e e5 0c 00 00    	jle    6dbf <susan_corners_quick+0xd3f>
    60da:	44 8b 5c 24 50       	mov    0x50(%rsp),%r11d
    60df:	45 8d 7b f9          	lea    -0x7(%r11),%r15d
    60e3:	41 83 ff 07          	cmp    $0x7,%r15d
    60e7:	0f 8e 47 04 00 00    	jle    6534 <susan_corners_quick+0x4b4>
    60ed:	49 63 fb             	movslq %r11d,%rdi
    60f0:	4c 8b 4c 24 48       	mov    0x48(%rsp),%r9
    60f5:	42 8d 0c 9d 00 00 00 	lea    0x0(,%r11,4),%ecx
    60fc:	00 
    60fd:	c7 84 24 c8 00 00 00 	movl   $0x7,0xc8(%rsp)
    6104:	07 00 00 00 
    6108:	48 8d 14 3f          	lea    (%rdi,%rdi,1),%rdx
    610c:	48 63 c9             	movslq %ecx,%rcx
    610f:	44 89 7c 24 58       	mov    %r15d,0x58(%rsp)
    6114:	48 8d 04 3a          	lea    (%rdx,%rdi,1),%rax
    6118:	4c 89 64 24 60       	mov    %r12,0x60(%rsp)
    611d:	48 8d 34 08          	lea    (%rax,%rcx,1),%rsi
    6121:	49 8d 44 84 04       	lea    0x4(%r12,%rax,4),%rax
    6126:	4d 8d 34 31          	lea    (%r9,%rsi,1),%r14
    612a:	48 8d 71 ff          	lea    -0x1(%rcx),%rsi
    612e:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
    6133:	b8 04 00 00 00       	mov    $0x4,%eax
    6138:	48 89 74 24 08       	mov    %rsi,0x8(%rsp)
    613d:	49 8d 71 07          	lea    0x7(%r9),%rsi
    6141:	48 29 f8             	sub    %rdi,%rax
    6144:	48 89 74 24 30       	mov    %rsi,0x30(%rsp)
    6149:	48 8d 72 06          	lea    0x6(%rdx),%rsi
    614d:	48 89 74 24 18       	mov    %rsi,0x18(%rsp)
    6152:	48 8d 77 05          	lea    0x5(%rdi),%rsi
    6156:	48 89 44 24 10       	mov    %rax,0x10(%rsp)
    615b:	41 8d 43 f1          	lea    -0xf(%r11),%eax
    615f:	48 89 74 24 20       	mov    %rsi,0x20(%rsp)
    6164:	48 83 c0 08          	add    $0x8,%rax
    6168:	49 89 c4             	mov    %rax,%r12
    616b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    6170:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
    6175:	4c 8b 4c 24 28       	mov    0x28(%rsp),%r9
    617a:	48 8b 54 24 30       	mov    0x30(%rsp),%rdx
    617f:	4c 8b 5c 24 18       	mov    0x18(%rsp),%r11
    6184:	48 8b 74 24 10       	mov    0x10(%rsp),%rsi
    6189:	48 01 c2             	add    %rax,%rdx
    618c:	49 8d 04 81          	lea    (%r9,%rax,4),%rax
    6190:	4b 8d 2c 33          	lea    (%r11,%r14,1),%rbp
    6194:	4c 8b 5c 24 20       	mov    0x20(%rsp),%r11
    6199:	48 89 44 24 38       	mov    %rax,0x38(%rsp)
    619e:	4a 8d 0c 36          	lea    (%rsi,%r14,1),%rcx
    61a2:	41 b9 07 00 00 00    	mov    $0x7,%r9d
    61a8:	49 8d 76 05          	lea    0x5(%r14),%rsi
    61ac:	4d 01 f3             	add    %r14,%r11
    61af:	90                   	nop
    61b0:	43 0f b6 04 0e       	movzbl (%r14,%r9,1),%eax
    61b5:	44 0f b6 12          	movzbl (%rdx),%r10d
    61b9:	44 0f b6 7a 01       	movzbl 0x1(%rdx),%r15d
    61be:	4c 01 e8             	add    %r13,%rax
    61c1:	49 89 c0             	mov    %rax,%r8
    61c4:	4d 29 d0             	sub    %r10,%r8
    61c7:	45 0f b6 10          	movzbl (%r8),%r10d
    61cb:	49 89 c0             	mov    %rax,%r8
    61ce:	4d 29 f8             	sub    %r15,%r8
    61d1:	44 0f b6 7a 02       	movzbl 0x2(%rdx),%r15d
    61d6:	45 0f b6 00          	movzbl (%r8),%r8d
    61da:	47 8d 44 02 64       	lea    0x64(%r10,%r8,1),%r8d
    61df:	49 89 c2             	mov    %rax,%r10
    61e2:	4d 29 fa             	sub    %r15,%r10
    61e5:	44 0f b6 7c 3a ff    	movzbl -0x1(%rdx,%rdi,1),%r15d
    61eb:	45 0f b6 12          	movzbl (%r10),%r10d
    61ef:	45 01 c2             	add    %r8d,%r10d
    61f2:	49 89 c0             	mov    %rax,%r8
    61f5:	4d 29 f8             	sub    %r15,%r8
    61f8:	44 0f b6 3c 3a       	movzbl (%rdx,%rdi,1),%r15d
    61fd:	45 0f b6 00          	movzbl (%r8),%r8d
    6201:	45 01 d0             	add    %r10d,%r8d
    6204:	49 89 c2             	mov    %rax,%r10
    6207:	4d 29 fa             	sub    %r15,%r10
    620a:	44 0f b6 7c 3a 01    	movzbl 0x1(%rdx,%rdi,1),%r15d
    6210:	45 0f b6 12          	movzbl (%r10),%r10d
    6214:	45 01 c2             	add    %r8d,%r10d
    6217:	49 89 c0             	mov    %rax,%r8
    621a:	4d 29 f8             	sub    %r15,%r8
    621d:	44 0f b6 7c 3a 02    	movzbl 0x2(%rdx,%rdi,1),%r15d
    6223:	45 0f b6 00          	movzbl (%r8),%r8d
    6227:	45 01 d0             	add    %r10d,%r8d
    622a:	49 89 c2             	mov    %rax,%r10
    622d:	4d 29 fa             	sub    %r15,%r10
    6230:	44 0f b6 7c 3a 03    	movzbl 0x3(%rdx,%rdi,1),%r15d
    6236:	45 0f b6 12          	movzbl (%r10),%r10d
    623a:	45 01 c2             	add    %r8d,%r10d
    623d:	49 89 c0             	mov    %rax,%r8
    6240:	4d 29 f8             	sub    %r15,%r8
    6243:	44 0f b6 39          	movzbl (%rcx),%r15d
    6247:	45 0f b6 00          	movzbl (%r8),%r8d
    624b:	45 01 d0             	add    %r10d,%r8d
    624e:	49 89 c2             	mov    %rax,%r10
    6251:	4d 29 fa             	sub    %r15,%r10
    6254:	44 0f b6 79 01       	movzbl 0x1(%rcx),%r15d
    6259:	45 0f b6 12          	movzbl (%r10),%r10d
    625d:	45 01 c2             	add    %r8d,%r10d
    6260:	49 89 c0             	mov    %rax,%r8
    6263:	4d 29 f8             	sub    %r15,%r8
    6266:	44 0f b6 79 02       	movzbl 0x2(%rcx),%r15d
    626b:	45 0f b6 00          	movzbl (%r8),%r8d
    626f:	45 01 d0             	add    %r10d,%r8d
    6272:	49 89 c2             	mov    %rax,%r10
    6275:	4d 29 fa             	sub    %r15,%r10
    6278:	44 0f b6 79 03       	movzbl 0x3(%rcx),%r15d
    627d:	45 0f b6 12          	movzbl (%r10),%r10d
    6281:	45 01 c2             	add    %r8d,%r10d
    6284:	49 89 c0             	mov    %rax,%r8
    6287:	4d 29 f8             	sub    %r15,%r8
    628a:	44 0f b6 79 04       	movzbl 0x4(%rcx),%r15d
    628f:	45 0f b6 00          	movzbl (%r8),%r8d
    6293:	45 01 d0             	add    %r10d,%r8d
    6296:	49 89 c2             	mov    %rax,%r10
    6299:	4d 29 fa             	sub    %r15,%r10
    629c:	44 0f b6 79 05       	movzbl 0x5(%rcx),%r15d
    62a1:	45 0f b6 12          	movzbl (%r10),%r10d
    62a5:	45 01 c2             	add    %r8d,%r10d
    62a8:	49 89 c0             	mov    %rax,%r8
    62ab:	4d 29 f8             	sub    %r15,%r8
    62ae:	44 0f b6 79 06       	movzbl 0x6(%rcx),%r15d
    62b3:	45 0f b6 00          	movzbl (%r8),%r8d
    62b7:	45 01 d0             	add    %r10d,%r8d
    62ba:	49 89 c2             	mov    %rax,%r10
    62bd:	4d 29 fa             	sub    %r15,%r10
    62c0:	44 0f b6 7e ff       	movzbl -0x1(%rsi),%r15d
    62c5:	45 0f b6 12          	movzbl (%r10),%r10d
    62c9:	45 01 c2             	add    %r8d,%r10d
    62cc:	49 89 c0             	mov    %rax,%r8
    62cf:	4d 29 f8             	sub    %r15,%r8
    62d2:	45 0f b6 00          	movzbl (%r8),%r8d
    62d6:	44 0f b6 3e          	movzbl (%rsi),%r15d
    62da:	45 01 d0             	add    %r10d,%r8d
    62dd:	49 89 c2             	mov    %rax,%r10
    62e0:	4d 29 fa             	sub    %r15,%r10
    62e3:	44 0f b6 7e 01       	movzbl 0x1(%rsi),%r15d
    62e8:	45 0f b6 12          	movzbl (%r10),%r10d
    62ec:	45 01 c2             	add    %r8d,%r10d
    62ef:	49 89 c0             	mov    %rax,%r8
    62f2:	4d 29 f8             	sub    %r15,%r8
    62f5:	45 0f b6 00          	movzbl (%r8),%r8d
    62f9:	45 01 d0             	add    %r10d,%r8d
    62fc:	41 39 d8             	cmp    %ebx,%r8d
    62ff:	0f 8d e3 01 00 00    	jge    64e8 <susan_corners_quick+0x468>
    6305:	44 0f b6 7e 03       	movzbl 0x3(%rsi),%r15d
    630a:	49 89 c2             	mov    %rax,%r10
    630d:	4d 29 fa             	sub    %r15,%r10
    6310:	45 0f b6 12          	movzbl (%r10),%r10d
    6314:	45 01 d0             	add    %r10d,%r8d
    6317:	44 39 c3             	cmp    %r8d,%ebx
    631a:	0f 8e c8 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6320:	44 0f b6 7e 04       	movzbl 0x4(%rsi),%r15d
    6325:	49 89 c2             	mov    %rax,%r10
    6328:	4d 29 fa             	sub    %r15,%r10
    632b:	45 0f b6 12          	movzbl (%r10),%r10d
    632f:	45 01 d0             	add    %r10d,%r8d
    6332:	44 39 c3             	cmp    %r8d,%ebx
    6335:	0f 8e ad 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    633b:	44 0f b6 7e 05       	movzbl 0x5(%rsi),%r15d
    6340:	49 89 c2             	mov    %rax,%r10
    6343:	4d 29 fa             	sub    %r15,%r10
    6346:	45 0f b6 12          	movzbl (%r10),%r10d
    634a:	45 01 d0             	add    %r10d,%r8d
    634d:	44 39 c3             	cmp    %r8d,%ebx
    6350:	0f 8e 92 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6356:	45 0f b6 7b ff       	movzbl -0x1(%r11),%r15d
    635b:	49 89 c2             	mov    %rax,%r10
    635e:	4d 29 fa             	sub    %r15,%r10
    6361:	45 0f b6 12          	movzbl (%r10),%r10d
    6365:	45 01 d0             	add    %r10d,%r8d
    6368:	44 39 c3             	cmp    %r8d,%ebx
    636b:	0f 8e 77 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6371:	45 0f b6 3b          	movzbl (%r11),%r15d
    6375:	49 89 c2             	mov    %rax,%r10
    6378:	4d 29 fa             	sub    %r15,%r10
    637b:	45 0f b6 12          	movzbl (%r10),%r10d
    637f:	45 01 d0             	add    %r10d,%r8d
    6382:	44 39 c3             	cmp    %r8d,%ebx
    6385:	0f 8e 5d 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    638b:	45 0f b6 7b 01       	movzbl 0x1(%r11),%r15d
    6390:	49 89 c2             	mov    %rax,%r10
    6393:	4d 29 fa             	sub    %r15,%r10
    6396:	45 0f b6 12          	movzbl (%r10),%r10d
    639a:	45 01 d0             	add    %r10d,%r8d
    639d:	44 39 c3             	cmp    %r8d,%ebx
    63a0:	0f 8e 42 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    63a6:	45 0f b6 7b 02       	movzbl 0x2(%r11),%r15d
    63ab:	49 89 c2             	mov    %rax,%r10
    63ae:	4d 29 fa             	sub    %r15,%r10
    63b1:	45 0f b6 12          	movzbl (%r10),%r10d
    63b5:	45 01 d0             	add    %r10d,%r8d
    63b8:	44 39 c3             	cmp    %r8d,%ebx
    63bb:	0f 8e 27 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    63c1:	45 0f b6 7b 03       	movzbl 0x3(%r11),%r15d
    63c6:	49 89 c2             	mov    %rax,%r10
    63c9:	4d 29 fa             	sub    %r15,%r10
    63cc:	45 0f b6 12          	movzbl (%r10),%r10d
    63d0:	45 01 c2             	add    %r8d,%r10d
    63d3:	44 39 d3             	cmp    %r10d,%ebx
    63d6:	0f 8e 0c 01 00 00    	jle    64e8 <susan_corners_quick+0x468>
    63dc:	45 0f b6 7b 04       	movzbl 0x4(%r11),%r15d
    63e1:	49 89 c0             	mov    %rax,%r8
    63e4:	4d 29 f8             	sub    %r15,%r8
    63e7:	45 0f b6 00          	movzbl (%r8),%r8d
    63eb:	45 01 d0             	add    %r10d,%r8d
    63ee:	44 39 c3             	cmp    %r8d,%ebx
    63f1:	0f 8e f1 00 00 00    	jle    64e8 <susan_corners_quick+0x468>
    63f7:	45 0f b6 7b 05       	movzbl 0x5(%r11),%r15d
    63fc:	49 89 c2             	mov    %rax,%r10
    63ff:	4d 29 fa             	sub    %r15,%r10
    6402:	45 0f b6 12          	movzbl (%r10),%r10d
    6406:	45 01 c2             	add    %r8d,%r10d
    6409:	44 39 d3             	cmp    %r10d,%ebx
    640c:	0f 8e d6 00 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6412:	44 0f b6 7d ff       	movzbl -0x1(%rbp),%r15d
    6417:	49 89 c0             	mov    %rax,%r8
    641a:	4d 29 f8             	sub    %r15,%r8
    641d:	45 0f b6 00          	movzbl (%r8),%r8d
    6421:	45 01 d0             	add    %r10d,%r8d
    6424:	44 39 c3             	cmp    %r8d,%ebx
    6427:	0f 8e bb 00 00 00    	jle    64e8 <susan_corners_quick+0x468>
    642d:	44 0f b6 7d 00       	movzbl 0x0(%rbp),%r15d
    6432:	49 89 c2             	mov    %rax,%r10
    6435:	4d 29 fa             	sub    %r15,%r10
    6438:	45 0f b6 12          	movzbl (%r10),%r10d
    643c:	45 01 c2             	add    %r8d,%r10d
    643f:	44 39 d3             	cmp    %r10d,%ebx
    6442:	0f 8e a0 00 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6448:	44 0f b6 7d 01       	movzbl 0x1(%rbp),%r15d
    644d:	49 89 c0             	mov    %rax,%r8
    6450:	4d 29 f8             	sub    %r15,%r8
    6453:	45 0f b6 00          	movzbl (%r8),%r8d
    6457:	45 01 d0             	add    %r10d,%r8d
    645a:	44 39 c3             	cmp    %r8d,%ebx
    645d:	0f 8e 85 00 00 00    	jle    64e8 <susan_corners_quick+0x468>
    6463:	44 0f b6 7d 02       	movzbl 0x2(%rbp),%r15d
    6468:	49 89 c2             	mov    %rax,%r10
    646b:	4d 29 fa             	sub    %r15,%r10
    646e:	45 0f b6 12          	movzbl (%r10),%r10d
    6472:	45 01 c2             	add    %r8d,%r10d
    6475:	44 39 d3             	cmp    %r10d,%ebx
    6478:	7e 6e                	jle    64e8 <susan_corners_quick+0x468>
    647a:	44 0f b6 7d 03       	movzbl 0x3(%rbp),%r15d
    647f:	49 89 c0             	mov    %rax,%r8
    6482:	4d 29 f8             	sub    %r15,%r8
    6485:	45 0f b6 00          	movzbl (%r8),%r8d
    6489:	45 01 d0             	add    %r10d,%r8d
    648c:	44 39 c3             	cmp    %r8d,%ebx
    648f:	7e 57                	jle    64e8 <susan_corners_quick+0x468>
    6491:	44 0f b6 7c 3d 00    	movzbl 0x0(%rbp,%rdi,1),%r15d
    6497:	49 89 c2             	mov    %rax,%r10
    649a:	4d 29 fa             	sub    %r15,%r10
    649d:	45 0f b6 12          	movzbl (%r10),%r10d
    64a1:	45 01 c2             	add    %r8d,%r10d
    64a4:	44 39 d3             	cmp    %r10d,%ebx
    64a7:	7e 3f                	jle    64e8 <susan_corners_quick+0x468>
    64a9:	44 0f b6 7c 3d 01    	movzbl 0x1(%rbp,%rdi,1),%r15d
    64af:	49 89 c0             	mov    %rax,%r8
    64b2:	4d 29 f8             	sub    %r15,%r8
    64b5:	45 0f b6 00          	movzbl (%r8),%r8d
    64b9:	45 01 d0             	add    %r10d,%r8d
    64bc:	44 39 c3             	cmp    %r8d,%ebx
    64bf:	7e 27                	jle    64e8 <susan_corners_quick+0x468>
    64c1:	44 0f b6 54 3d 02    	movzbl 0x2(%rbp,%rdi,1),%r10d
    64c7:	4c 29 d0             	sub    %r10,%rax
    64ca:	0f b6 00             	movzbl (%rax),%eax
    64cd:	44 01 c0             	add    %r8d,%eax
    64d0:	39 c3                	cmp    %eax,%ebx
    64d2:	7e 14                	jle    64e8 <susan_corners_quick+0x468>
    64d4:	41 89 d8             	mov    %ebx,%r8d
    64d7:	41 29 c0             	sub    %eax,%r8d
    64da:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    64df:	46 89 04 88          	mov    %r8d,(%rax,%r9,4)
    64e3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    64e8:	49 83 c1 01          	add    $0x1,%r9
    64ec:	48 83 c2 01          	add    $0x1,%rdx
    64f0:	48 83 c1 01          	add    $0x1,%rcx
    64f4:	48 83 c6 01          	add    $0x1,%rsi
    64f8:	48 83 c5 01          	add    $0x1,%rbp
    64fc:	49 83 c3 01          	add    $0x1,%r11
    6500:	4d 39 e1             	cmp    %r12,%r9
    6503:	0f 85 a7 fc ff ff    	jne    61b0 <susan_corners_quick+0x130>
    6509:	83 84 24 c8 00 00 00 	addl   $0x1,0xc8(%rsp)
    6510:	01 
    6511:	49 01 fe             	add    %rdi,%r14
    6514:	8b 84 24 c8 00 00 00 	mov    0xc8(%rsp),%eax
    651b:	48 01 7c 24 08       	add    %rdi,0x8(%rsp)
    6520:	3b 44 24 04          	cmp    0x4(%rsp),%eax
    6524:	0f 85 46 fc ff ff    	jne    6170 <susan_corners_quick+0xf0>
    652a:	44 8b 7c 24 58       	mov    0x58(%rsp),%r15d
    652f:	4c 8b 64 24 60       	mov    0x60(%rsp),%r12
    6534:	44 8b 5c 24 50       	mov    0x50(%rsp),%r11d
    6539:	c7 44 24 10 00 00 00 	movl   $0x0,0x10(%rsp)
    6540:	00 
    6541:	4c 8b 6c 24 48       	mov    0x48(%rsp),%r13
    6546:	43 8d 04 1b          	lea    (%r11,%r11,1),%eax
    654a:	42 8d 2c 9d 00 00 00 	lea    0x0(,%r11,4),%ebp
    6551:	00 
    6552:	89 84 24 c8 00 00 00 	mov    %eax,0xc8(%rsp)
    6559:	46 8d 34 dd 00 00 00 	lea    0x0(,%r11,8),%r14d
    6560:	00 
    6561:	b8 07 00 00 00       	mov    $0x7,%eax
    6566:	89 eb                	mov    %ebp,%ebx
    6568:	66 0f 6e c0          	movd   %eax,%xmm0
    656c:	45 89 f1             	mov    %r14d,%r9d
    656f:	4c 89 e5             	mov    %r12,%rbp
    6572:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    6578:	46 8d 04 1b          	lea    (%rbx,%r11,1),%r8d
    657c:	41 83 ff 07          	cmp    $0x7,%r15d
    6580:	0f 8e ee 07 00 00    	jle    6d74 <susan_corners_quick+0xcf4>
    6586:	46 8d 04 1b          	lea    (%rbx,%r11,1),%r8d
    658a:	44 89 c8             	mov    %r9d,%eax
    658d:	b9 07 00 00 00       	mov    $0x7,%ecx
    6592:	43 8d 3c 18          	lea    (%r8,%r11,1),%edi
    6596:	44 29 d8             	sub    %r11d,%eax
    6599:	89 7c 24 08          	mov    %edi,0x8(%rsp)
    659d:	8b bc 24 c8 00 00 00 	mov    0xc8(%rsp),%edi
    65a4:	44 8d 14 38          	lea    (%rax,%rdi,1),%r10d
    65a8:	48 98                	cltq   
    65aa:	47 8d 34 1a          	lea    (%r10,%r11,1),%r14d
    65ae:	48 8d 74 85 00       	lea    0x0(%rbp,%rax,4),%rsi
    65b3:	4d 8d 64 05 05       	lea    0x5(%r13,%rax,1),%r12
    65b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    65bf:	00 
    65c0:	8b 46 1c             	mov    0x1c(%rsi),%eax
    65c3:	66 0f 6e c9          	movd   %ecx,%xmm1
    65c7:	66 0f 62 c8          	punpckldq %xmm0,%xmm1
    65cb:	85 c0                	test   %eax,%eax
    65cd:	0f 8e 8d 07 00 00    	jle    6d60 <susan_corners_quick+0xce0>
    65d3:	8d 14 19             	lea    (%rcx,%rbx,1),%edx
    65d6:	48 63 d2             	movslq %edx,%rdx
    65d9:	48 8d 3c 95 00 00 00 	lea    0x0(,%rdx,4),%rdi
    65e0:	00 
    65e1:	39 44 95 f4          	cmp    %eax,-0xc(%rbp,%rdx,4)
    65e5:	0f 8d 75 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    65eb:	39 44 3d f8          	cmp    %eax,-0x8(%rbp,%rdi,1)
    65ef:	0f 8d 6b 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    65f5:	39 44 3d fc          	cmp    %eax,-0x4(%rbp,%rdi,1)
    65f9:	0f 8d 61 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    65ff:	39 44 95 00          	cmp    %eax,0x0(%rbp,%rdx,4)
    6603:	0f 8d 57 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6609:	39 44 3d 04          	cmp    %eax,0x4(%rbp,%rdi,1)
    660d:	0f 8d 4d 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6613:	39 44 3d 08          	cmp    %eax,0x8(%rbp,%rdi,1)
    6617:	0f 8d 43 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    661d:	39 44 3d 0c          	cmp    %eax,0xc(%rbp,%rdi,1)
    6621:	0f 8d 39 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6627:	41 8d 14 08          	lea    (%r8,%rcx,1),%edx
    662b:	48 63 fa             	movslq %edx,%rdi
    662e:	48 8d 14 bd 00 00 00 	lea    0x0(,%rdi,4),%rdx
    6635:	00 
    6636:	39 44 bd f4          	cmp    %eax,-0xc(%rbp,%rdi,4)
    663a:	0f 8d 20 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6640:	39 44 15 f8          	cmp    %eax,-0x8(%rbp,%rdx,1)
    6644:	0f 8d 16 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    664a:	39 44 15 fc          	cmp    %eax,-0x4(%rbp,%rdx,1)
    664e:	0f 8d 0c 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6654:	39 44 bd 00          	cmp    %eax,0x0(%rbp,%rdi,4)
    6658:	0f 8d 02 07 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    665e:	48 89 7c 24 20       	mov    %rdi,0x20(%rsp)
    6663:	48 83 c7 01          	add    $0x1,%rdi
    6667:	48 89 7c 24 58       	mov    %rdi,0x58(%rsp)
    666c:	39 44 15 04          	cmp    %eax,0x4(%rbp,%rdx,1)
    6670:	0f 8d ea 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6676:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    667b:	48 83 c7 02          	add    $0x2,%rdi
    667f:	48 89 7c 24 60       	mov    %rdi,0x60(%rsp)
    6684:	39 44 15 08          	cmp    %eax,0x8(%rbp,%rdx,1)
    6688:	0f 8d d2 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    668e:	39 44 15 0c          	cmp    %eax,0xc(%rbp,%rdx,1)
    6692:	0f 8d c8 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6698:	8b 54 24 08          	mov    0x8(%rsp),%edx
    669c:	01 ca                	add    %ecx,%edx
    669e:	48 63 d2             	movslq %edx,%rdx
    66a1:	48 89 d7             	mov    %rdx,%rdi
    66a4:	48 c1 e2 02          	shl    $0x2,%rdx
    66a8:	39 44 bd f4          	cmp    %eax,-0xc(%rbp,%rdi,4)
    66ac:	0f 8d ae 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    66b2:	39 44 15 f8          	cmp    %eax,-0x8(%rbp,%rdx,1)
    66b6:	0f 8d a4 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    66bc:	39 44 15 fc          	cmp    %eax,-0x4(%rbp,%rdx,1)
    66c0:	0f 8d 9a 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    66c6:	39 44 bd 00          	cmp    %eax,0x0(%rbp,%rdi,4)
    66ca:	0f 8d 90 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    66d0:	48 89 7c 24 28       	mov    %rdi,0x28(%rsp)
    66d5:	48 83 c7 01          	add    $0x1,%rdi
    66d9:	48 89 7c 24 78       	mov    %rdi,0x78(%rsp)
    66de:	39 44 15 04          	cmp    %eax,0x4(%rbp,%rdx,1)
    66e2:	0f 8d 78 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    66e8:	48 8b 7c 24 28       	mov    0x28(%rsp),%rdi
    66ed:	48 83 c7 02          	add    $0x2,%rdi
    66f1:	48 89 bc 24 80 00 00 	mov    %rdi,0x80(%rsp)
    66f8:	00 
    66f9:	39 44 15 08          	cmp    %eax,0x8(%rbp,%rdx,1)
    66fd:	0f 8d 5d 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6703:	39 44 15 0c          	cmp    %eax,0xc(%rbp,%rdx,1)
    6707:	0f 8d 53 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    670d:	39 46 10             	cmp    %eax,0x10(%rsi)
    6710:	0f 8d 4a 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6716:	39 46 14             	cmp    %eax,0x14(%rsi)
    6719:	0f 8d 41 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    671f:	39 46 18             	cmp    %eax,0x18(%rsi)
    6722:	0f 8d 38 06 00 00    	jge    6d60 <susan_corners_quick+0xce0>
    6728:	39 46 20             	cmp    %eax,0x20(%rsi)
    672b:	0f 8f 2f 06 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6731:	39 46 24             	cmp    %eax,0x24(%rsi)
    6734:	0f 8f 26 06 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    673a:	39 46 28             	cmp    %eax,0x28(%rsi)
    673d:	0f 8f 1d 06 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6743:	42 8d 14 09          	lea    (%rcx,%r9,1),%edx
    6747:	48 63 fa             	movslq %edx,%rdi
    674a:	48 8d 14 bd 00 00 00 	lea    0x0(,%rdi,4),%rdx
    6751:	00 
    6752:	39 44 bd f4          	cmp    %eax,-0xc(%rbp,%rdi,4)
    6756:	0f 8f 04 06 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    675c:	39 44 15 f8          	cmp    %eax,-0x8(%rbp,%rdx,1)
    6760:	0f 8f fa 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6766:	39 44 15 fc          	cmp    %eax,-0x4(%rbp,%rdx,1)
    676a:	0f 8f f0 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6770:	39 44 bd 00          	cmp    %eax,0x0(%rbp,%rdi,4)
    6774:	0f 8f e6 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    677a:	48 89 7c 24 30       	mov    %rdi,0x30(%rsp)
    677f:	48 83 c7 01          	add    $0x1,%rdi
    6783:	48 89 bc 24 98 00 00 	mov    %rdi,0x98(%rsp)
    678a:	00 
    678b:	39 44 15 04          	cmp    %eax,0x4(%rbp,%rdx,1)
    678f:	0f 8f cb 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6795:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    679a:	48 83 c7 02          	add    $0x2,%rdi
    679e:	48 89 bc 24 a0 00 00 	mov    %rdi,0xa0(%rsp)
    67a5:	00 
    67a6:	39 44 15 08          	cmp    %eax,0x8(%rbp,%rdx,1)
    67aa:	0f 8f b0 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67b0:	39 44 15 0c          	cmp    %eax,0xc(%rbp,%rdx,1)
    67b4:	0f 8f a6 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67ba:	41 8d 14 0a          	lea    (%r10,%rcx,1),%edx
    67be:	48 63 d2             	movslq %edx,%rdx
    67c1:	48 89 d7             	mov    %rdx,%rdi
    67c4:	48 c1 e2 02          	shl    $0x2,%rdx
    67c8:	39 44 bd f4          	cmp    %eax,-0xc(%rbp,%rdi,4)
    67cc:	0f 8f 8e 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67d2:	39 44 15 f8          	cmp    %eax,-0x8(%rbp,%rdx,1)
    67d6:	0f 8f 84 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67dc:	39 44 15 fc          	cmp    %eax,-0x4(%rbp,%rdx,1)
    67e0:	0f 8f 7a 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67e6:	39 44 bd 00          	cmp    %eax,0x0(%rbp,%rdi,4)
    67ea:	0f 8f 70 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    67f0:	48 89 7c 24 38       	mov    %rdi,0x38(%rsp)
    67f5:	48 83 c7 01          	add    $0x1,%rdi
    67f9:	48 89 bc 24 b0 00 00 	mov    %rdi,0xb0(%rsp)
    6800:	00 
    6801:	39 44 15 04          	cmp    %eax,0x4(%rbp,%rdx,1)
    6805:	0f 8f 55 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    680b:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
    6810:	48 83 c7 02          	add    $0x2,%rdi
    6814:	48 89 bc 24 b8 00 00 	mov    %rdi,0xb8(%rsp)
    681b:	00 
    681c:	39 44 15 08          	cmp    %eax,0x8(%rbp,%rdx,1)
    6820:	0f 8f 3a 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6826:	39 44 15 0c          	cmp    %eax,0xc(%rbp,%rdx,1)
    682a:	0f 8f 30 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6830:	41 8d 14 0e          	lea    (%r14,%rcx,1),%edx
    6834:	48 63 fa             	movslq %edx,%rdi
    6837:	48 8d 14 bd 00 00 00 	lea    0x0(,%rdi,4),%rdx
    683e:	00 
    683f:	39 44 bd f4          	cmp    %eax,-0xc(%rbp,%rdi,4)
    6843:	0f 8f 17 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6849:	39 44 15 f8          	cmp    %eax,-0x8(%rbp,%rdx,1)
    684d:	0f 8f 0d 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6853:	39 44 15 fc          	cmp    %eax,-0x4(%rbp,%rdx,1)
    6857:	0f 8f 03 05 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    685d:	39 44 bd 00          	cmp    %eax,0x0(%rbp,%rdi,4)
    6861:	0f 8f f9 04 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6867:	39 44 15 04          	cmp    %eax,0x4(%rbp,%rdx,1)
    686b:	0f 8f ef 04 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6871:	39 44 15 08          	cmp    %eax,0x8(%rbp,%rdx,1)
    6875:	0f 8f e5 04 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    687b:	39 44 15 0c          	cmp    %eax,0xc(%rbp,%rdx,1)
    687f:	0f 8f db 04 00 00    	jg     6d60 <susan_corners_quick+0xce0>
    6885:	48 63 44 24 10       	movslq 0x10(%rsp),%rax
    688a:	48 8b 7c 24 40       	mov    0x40(%rsp),%rdi
    688f:	48 6b c0 18          	imul   $0x18,%rax,%rax
    6893:	48 01 c7             	add    %rax,%rdi
    6896:	c7 47 08 00 00 00 00 	movl   $0x0,0x8(%rdi)
    689d:	48 89 7c 24 18       	mov    %rdi,0x18(%rsp)
    68a2:	66 0f d6 0f          	movq   %xmm1,(%rdi)
    68a6:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
    68ab:	49 8d 44 3d fe       	lea    -0x2(%r13,%rdi,1),%rax
    68b0:	49 8d 54 3d ff       	lea    -0x1(%r13,%rdi,1),%rdx
    68b5:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
    68ba:	48 89 f8             	mov    %rdi,%rax
    68bd:	48 8b 7c 24 30       	mov    0x30(%rsp),%rdi
    68c2:	4c 01 e8             	add    %r13,%rax
    68c5:	48 89 54 24 48       	mov    %rdx,0x48(%rsp)
    68ca:	48 8b 54 24 60       	mov    0x60(%rsp),%rdx
    68cf:	48 89 44 24 50       	mov    %rax,0x50(%rsp)
    68d4:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    68d9:	4c 01 ea             	add    %r13,%rdx
    68dc:	4c 01 e8             	add    %r13,%rax
    68df:	48 89 54 24 60       	mov    %rdx,0x60(%rsp)
    68e4:	48 89 44 24 58       	mov    %rax,0x58(%rsp)
    68e9:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    68ee:	49 8d 54 05 fe       	lea    -0x2(%r13,%rax,1),%rdx
    68f3:	48 89 54 24 28       	mov    %rdx,0x28(%rsp)
    68f8:	49 8d 54 05 ff       	lea    -0x1(%r13,%rax,1),%rdx
    68fd:	4c 01 e8             	add    %r13,%rax
    6900:	48 89 44 24 70       	mov    %rax,0x70(%rsp)
    6905:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    690a:	48 89 54 24 68       	mov    %rdx,0x68(%rsp)
    690f:	48 8b 94 24 80 00 00 	mov    0x80(%rsp),%rdx
    6916:	00 
    6917:	4c 01 e8             	add    %r13,%rax
    691a:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
    691f:	49 8d 44 3d fe       	lea    -0x2(%r13,%rdi,1),%rax
    6924:	4c 01 ea             	add    %r13,%rdx
    6927:	48 89 44 24 30       	mov    %rax,0x30(%rsp)
    692c:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    6933:	00 
    6934:	48 89 94 24 80 00 00 	mov    %rdx,0x80(%rsp)
    693b:	00 
    693c:	49 8d 54 3d ff       	lea    -0x1(%r13,%rdi,1),%rdx
    6941:	4c 01 ef             	add    %r13,%rdi
    6944:	4c 01 e8             	add    %r13,%rax
    6947:	48 89 bc 24 90 00 00 	mov    %rdi,0x90(%rsp)
    694e:	00 
    694f:	48 89 c7             	mov    %rax,%rdi
    6952:	48 8b 84 24 a0 00 00 	mov    0xa0(%rsp),%rax
    6959:	00 
    695a:	48 89 94 24 88 00 00 	mov    %rdx,0x88(%rsp)
    6961:	00 
    6962:	4c 01 e8             	add    %r13,%rax
    6965:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
    696c:	00 
    696d:	48 8b 44 24 38       	mov    0x38(%rsp),%rax
    6972:	49 8d 54 05 fe       	lea    -0x2(%r13,%rax,1),%rdx
    6977:	48 89 54 24 38       	mov    %rdx,0x38(%rsp)
    697c:	49 8d 54 05 ff       	lea    -0x1(%r13,%rax,1),%rdx
    6981:	4c 01 e8             	add    %r13,%rax
    6984:	48 89 84 24 a8 00 00 	mov    %rax,0xa8(%rsp)
    698b:	00 
    698c:	48 89 94 24 a0 00 00 	mov    %rdx,0xa0(%rsp)
    6993:	00 
    6994:	48 8b 94 24 b0 00 00 	mov    0xb0(%rsp),%rdx
    699b:	00 
    699c:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
    69a1:	4c 01 ea             	add    %r13,%rdx
    69a4:	48 89 94 24 b0 00 00 	mov    %rdx,0xb0(%rsp)
    69ab:	00 
    69ac:	48 8b 94 24 b8 00 00 	mov    0xb8(%rsp),%rdx
    69b3:	00 
    69b4:	4c 01 ea             	add    %r13,%rdx
    69b7:	48 89 94 24 b8 00 00 	mov    %rdx,0xb8(%rsp)
    69be:	00 
    69bf:	0f b6 10             	movzbl (%rax),%edx
    69c2:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    69c7:	0f b6 00             	movzbl (%rax),%eax
    69ca:	01 d0                	add    %edx,%eax
    69cc:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
    69d1:	0f b6 12             	movzbl (%rdx),%edx
    69d4:	01 c2                	add    %eax,%edx
    69d6:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    69db:	0f b6 00             	movzbl (%rax),%eax
    69de:	01 d0                	add    %edx,%eax
    69e0:	48 8b 54 24 60       	mov    0x60(%rsp),%rdx
    69e5:	0f b6 12             	movzbl (%rdx),%edx
    69e8:	01 c2                	add    %eax,%edx
    69ea:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
    69ef:	0f b6 00             	movzbl (%rax),%eax
    69f2:	01 d0                	add    %edx,%eax
    69f4:	48 8b 54 24 68       	mov    0x68(%rsp),%rdx
    69f9:	0f b6 12             	movzbl (%rdx),%edx
    69fc:	01 c2                	add    %eax,%edx
    69fe:	48 8b 44 24 70       	mov    0x70(%rsp),%rax
    6a03:	0f b6 00             	movzbl (%rax),%eax
    6a06:	01 d0                	add    %edx,%eax
    6a08:	48 8b 54 24 78       	mov    0x78(%rsp),%rdx
    6a0d:	0f b6 12             	movzbl (%rdx),%edx
    6a10:	01 c2                	add    %eax,%edx
    6a12:	48 8b 84 24 80 00 00 	mov    0x80(%rsp),%rax
    6a19:	00 
    6a1a:	0f b6 00             	movzbl (%rax),%eax
    6a1d:	01 d0                	add    %edx,%eax
    6a1f:	41 0f b6 14 24       	movzbl (%r12),%edx
    6a24:	01 c2                	add    %eax,%edx
    6a26:	41 0f b6 44 24 01    	movzbl 0x1(%r12),%eax
    6a2c:	01 d0                	add    %edx,%eax
    6a2e:	41 0f b6 54 24 02    	movzbl 0x2(%r12),%edx
    6a34:	01 c2                	add    %eax,%edx
    6a36:	41 0f b6 44 24 03    	movzbl 0x3(%r12),%eax
    6a3c:	01 d0                	add    %edx,%eax
    6a3e:	41 0f b6 54 24 04    	movzbl 0x4(%r12),%edx
    6a44:	01 c2                	add    %eax,%edx
    6a46:	48 8b 44 24 30       	mov    0x30(%rsp),%rax
    6a4b:	0f b6 00             	movzbl (%rax),%eax
    6a4e:	01 d0                	add    %edx,%eax
    6a50:	48 8b 94 24 88 00 00 	mov    0x88(%rsp),%rdx
    6a57:	00 
    6a58:	0f b6 12             	movzbl (%rdx),%edx
    6a5b:	48 89 bc 24 c0 00 00 	mov    %rdi,0xc0(%rsp)
    6a62:	00 
    6a63:	01 c2                	add    %eax,%edx
    6a65:	48 8b 84 24 90 00 00 	mov    0x90(%rsp),%rax
    6a6c:	00 
    6a6d:	0f b6 00             	movzbl (%rax),%eax
    6a70:	01 d0                	add    %edx,%eax
    6a72:	0f b6 17             	movzbl (%rdi),%edx
    6a75:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
    6a7a:	01 c2                	add    %eax,%edx
    6a7c:	48 8b 84 24 98 00 00 	mov    0x98(%rsp),%rax
    6a83:	00 
    6a84:	0f b6 00             	movzbl (%rax),%eax
    6a87:	01 d0                	add    %edx,%eax
    6a89:	0f b6 17             	movzbl (%rdi),%edx
    6a8c:	48 8b bc 24 a0 00 00 	mov    0xa0(%rsp),%rdi
    6a93:	00 
    6a94:	01 c2                	add    %eax,%edx
    6a96:	0f b6 07             	movzbl (%rdi),%eax
    6a99:	48 8b bc 24 a8 00 00 	mov    0xa8(%rsp),%rdi
    6aa0:	00 
    6aa1:	01 d0                	add    %edx,%eax
    6aa3:	0f b6 17             	movzbl (%rdi),%edx
    6aa6:	bf 19 00 00 00       	mov    $0x19,%edi
    6aab:	01 c2                	add    %eax,%edx
    6aad:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    6ab4:	00 
    6ab5:	0f b6 00             	movzbl (%rax),%eax
    6ab8:	01 d0                	add    %edx,%eax
    6aba:	48 8b 94 24 b8 00 00 	mov    0xb8(%rsp),%rdx
    6ac1:	00 
    6ac2:	0f b6 12             	movzbl (%rdx),%edx
    6ac5:	01 d0                	add    %edx,%eax
    6ac7:	99                   	cltd   
    6ac8:	f7 ff                	idiv   %edi
    6aca:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
    6acf:	48 8b 54 24 60       	mov    0x60(%rsp),%rdx
    6ad4:	89 47 14             	mov    %eax,0x14(%rdi)
    6ad7:	0f b6 12             	movzbl (%rdx),%edx
    6ada:	89 54 24 60          	mov    %edx,0x60(%rsp)
    6ade:	48 8b 94 24 80 00 00 	mov    0x80(%rsp),%rdx
    6ae5:	00 
    6ae6:	0f b6 12             	movzbl (%rdx),%edx
    6ae9:	89 94 24 80 00 00 00 	mov    %edx,0x80(%rsp)
    6af0:	48 8b 94 24 98 00 00 	mov    0x98(%rsp),%rdx
    6af7:	00 
    6af8:	0f b6 02             	movzbl (%rdx),%eax
    6afb:	48 8b 94 24 b8 00 00 	mov    0xb8(%rsp),%rdx
    6b02:	00 
    6b03:	89 84 24 98 00 00 00 	mov    %eax,0x98(%rsp)
    6b0a:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
    6b0f:	0f b6 12             	movzbl (%rdx),%edx
    6b12:	0f b6 00             	movzbl (%rax),%eax
    6b15:	89 d7                	mov    %edx,%edi
    6b17:	89 84 24 b8 00 00 00 	mov    %eax,0xb8(%rsp)
    6b1e:	48 8b 54 24 28       	mov    0x28(%rsp),%rdx
    6b23:	48 8b 44 24 30       	mov    0x30(%rsp),%rax
    6b28:	89 7c 24 20          	mov    %edi,0x20(%rsp)
    6b2c:	0f b6 12             	movzbl (%rdx),%edx
    6b2f:	89 54 24 28          	mov    %edx,0x28(%rsp)
    6b33:	0f b6 10             	movzbl (%rax),%edx
    6b36:	89 54 24 30          	mov    %edx,0x30(%rsp)
    6b3a:	48 8b 54 24 38       	mov    0x38(%rsp),%rdx
    6b3f:	0f b6 12             	movzbl (%rdx),%edx
    6b42:	89 54 24 38          	mov    %edx,0x38(%rsp)
    6b46:	8b 54 24 60          	mov    0x60(%rsp),%edx
    6b4a:	03 94 24 80 00 00 00 	add    0x80(%rsp),%edx
    6b51:	89 d0                	mov    %edx,%eax
    6b53:	41 0f b6 54 24 04    	movzbl 0x4(%r12),%edx
    6b59:	01 d0                	add    %edx,%eax
    6b5b:	03 84 24 98 00 00 00 	add    0x98(%rsp),%eax
    6b62:	89 c2                	mov    %eax,%edx
    6b64:	8b 84 24 b8 00 00 00 	mov    0xb8(%rsp),%eax
    6b6b:	03 44 24 28          	add    0x28(%rsp),%eax
    6b6f:	01 fa                	add    %edi,%edx
    6b71:	89 d7                	mov    %edx,%edi
    6b73:	41 0f b6 14 24       	movzbl (%r12),%edx
    6b78:	01 d0                	add    %edx,%eax
    6b7a:	89 fa                	mov    %edi,%edx
    6b7c:	03 44 24 30          	add    0x30(%rsp),%eax
    6b80:	03 44 24 38          	add    0x38(%rsp),%eax
    6b84:	29 c2                	sub    %eax,%edx
    6b86:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
    6b8b:	0f b6 00             	movzbl (%rax),%eax
    6b8e:	89 44 24 58          	mov    %eax,0x58(%rsp)
    6b92:	48 8b 44 24 78       	mov    0x78(%rsp),%rax
    6b97:	0f b6 00             	movzbl (%rax),%eax
    6b9a:	89 44 24 78          	mov    %eax,0x78(%rsp)
    6b9e:	48 8b 84 24 c0 00 00 	mov    0xc0(%rsp),%rax
    6ba5:	00 
    6ba6:	0f b6 00             	movzbl (%rax),%eax
    6ba9:	89 84 24 c0 00 00 00 	mov    %eax,0xc0(%rsp)
    6bb0:	48 8b 84 24 b0 00 00 	mov    0xb0(%rsp),%rax
    6bb7:	00 
    6bb8:	0f b6 00             	movzbl (%rax),%eax
    6bbb:	89 84 24 b0 00 00 00 	mov    %eax,0xb0(%rsp)
    6bc2:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
    6bc7:	0f b6 00             	movzbl (%rax),%eax
    6bca:	89 44 24 48          	mov    %eax,0x48(%rsp)
    6bce:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
    6bd3:	0f b6 00             	movzbl (%rax),%eax
    6bd6:	89 44 24 68          	mov    %eax,0x68(%rsp)
    6bda:	48 8b 84 24 88 00 00 	mov    0x88(%rsp),%rax
    6be1:	00 
    6be2:	0f b6 00             	movzbl (%rax),%eax
    6be5:	89 84 24 88 00 00 00 	mov    %eax,0x88(%rsp)
    6bec:	48 8b 84 24 a0 00 00 	mov    0xa0(%rsp),%rax
    6bf3:	00 
    6bf4:	89 94 24 a0 00 00 00 	mov    %edx,0xa0(%rsp)
    6bfb:	0f b6 00             	movzbl (%rax),%eax
    6bfe:	89 c7                	mov    %eax,%edi
    6c00:	8b 44 24 58          	mov    0x58(%rsp),%eax
    6c04:	01 d0                	add    %edx,%eax
    6c06:	41 0f b6 54 24 03    	movzbl 0x3(%r12),%edx
    6c0c:	03 44 24 78          	add    0x78(%rsp),%eax
    6c10:	01 d0                	add    %edx,%eax
    6c12:	8b 94 24 b0 00 00 00 	mov    0xb0(%rsp),%edx
    6c19:	03 84 24 c0 00 00 00 	add    0xc0(%rsp),%eax
    6c20:	01 c2                	add    %eax,%edx
    6c22:	8b 44 24 48          	mov    0x48(%rsp),%eax
    6c26:	03 44 24 68          	add    0x68(%rsp),%eax
    6c2a:	89 94 24 cc 00 00 00 	mov    %edx,0xcc(%rsp)
    6c31:	41 0f b6 54 24 01    	movzbl 0x1(%r12),%edx
    6c37:	01 d0                	add    %edx,%eax
    6c39:	8b 94 24 cc 00 00 00 	mov    0xcc(%rsp),%edx
    6c40:	03 84 24 88 00 00 00 	add    0x88(%rsp),%eax
    6c47:	01 f8                	add    %edi,%eax
    6c49:	29 c2                	sub    %eax,%edx
    6c4b:	8b 44 24 38          	mov    0x38(%rsp),%eax
    6c4f:	89 94 24 cc 00 00 00 	mov    %edx,0xcc(%rsp)
    6c56:	48 8b 94 24 a8 00 00 	mov    0xa8(%rsp),%rdx
    6c5d:	00 
    6c5e:	01 f8                	add    %edi,%eax
    6c60:	0f b6 12             	movzbl (%rdx),%edx
    6c63:	01 d0                	add    %edx,%eax
    6c65:	48 8b 54 24 50       	mov    0x50(%rsp),%rdx
    6c6a:	03 84 24 b0 00 00 00 	add    0xb0(%rsp),%eax
    6c71:	03 44 24 20          	add    0x20(%rsp),%eax
    6c75:	0f b6 12             	movzbl (%rdx),%edx
    6c78:	89 c7                	mov    %eax,%edi
    6c7a:	8b 84 24 b8 00 00 00 	mov    0xb8(%rsp),%eax
    6c81:	03 44 24 48          	add    0x48(%rsp),%eax
    6c85:	01 d0                	add    %edx,%eax
    6c87:	89 fa                	mov    %edi,%edx
    6c89:	03 44 24 58          	add    0x58(%rsp),%eax
    6c8d:	03 44 24 60          	add    0x60(%rsp),%eax
    6c91:	29 c2                	sub    %eax,%edx
    6c93:	83 44 24 10 01       	addl   $0x1,0x10(%rsp)
    6c98:	89 d0                	mov    %edx,%eax
    6c9a:	8b 54 24 30          	mov    0x30(%rsp),%edx
    6c9e:	89 44 24 20          	mov    %eax,0x20(%rsp)
    6ca2:	01 c2                	add    %eax,%edx
    6ca4:	8b 84 24 88 00 00 00 	mov    0x88(%rsp),%eax
    6cab:	01 d0                	add    %edx,%eax
    6cad:	48 8b 94 24 90 00 00 	mov    0x90(%rsp),%rdx
    6cb4:	00 
    6cb5:	0f b6 12             	movzbl (%rdx),%edx
    6cb8:	01 d0                	add    %edx,%eax
    6cba:	48 8b 54 24 70       	mov    0x70(%rsp),%rdx
    6cbf:	03 84 24 c0 00 00 00 	add    0xc0(%rsp),%eax
    6cc6:	03 84 24 98 00 00 00 	add    0x98(%rsp),%eax
    6ccd:	0f b6 12             	movzbl (%rdx),%edx
    6cd0:	89 c7                	mov    %eax,%edi
    6cd2:	8b 44 24 28          	mov    0x28(%rsp),%eax
    6cd6:	03 44 24 68          	add    0x68(%rsp),%eax
    6cda:	01 d0                	add    %edx,%eax
    6cdc:	89 fa                	mov    %edi,%edx
    6cde:	03 44 24 78          	add    0x78(%rsp),%eax
    6ce2:	03 84 24 80 00 00 00 	add    0x80(%rsp),%eax
    6ce9:	29 c2                	sub    %eax,%edx
    6ceb:	8b 84 24 cc 00 00 00 	mov    0xcc(%rsp),%eax
    6cf2:	03 84 24 a0 00 00 00 	add    0xa0(%rsp),%eax
    6cf9:	bf 0f 00 00 00       	mov    $0xf,%edi
    6cfe:	89 54 24 28          	mov    %edx,0x28(%rsp)
    6d02:	99                   	cltd   
    6d03:	f7 ff                	idiv   %edi
    6d05:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
    6d0a:	89 47 0c             	mov    %eax,0xc(%rdi)
    6d0d:	8b 44 24 28          	mov    0x28(%rsp),%eax
    6d11:	bf 0f 00 00 00       	mov    $0xf,%edi
    6d16:	03 44 24 20          	add    0x20(%rsp),%eax
    6d1a:	99                   	cltd   
    6d1b:	f7 ff                	idiv   %edi
    6d1d:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
    6d22:	89 47 10             	mov    %eax,0x10(%rdi)
    6d25:	8b 7c 24 10          	mov    0x10(%rsp),%edi
    6d29:	81 ff 98 3a 00 00    	cmp    $0x3a98,%edi
    6d2f:	75 2f                	jne    6d60 <susan_corners_quick+0xce0>
    6d31:	48 8b 0d e8 22 00 00 	mov    0x22e8(%rip),%rcx        # 9020 <stderr@GLIBC_2.2.5>
    6d38:	ba 12 00 00 00       	mov    $0x12,%edx
    6d3d:	be 01 00 00 00       	mov    $0x1,%esi
    6d42:	48 8d 3d d8 07 00 00 	lea    0x7d8(%rip),%rdi        # 7521 <_IO_stdin_used+0x521>
    6d49:	e8 32 a5 ff ff       	call   1280 <fwrite@plt>
    6d4e:	bf 01 00 00 00       	mov    $0x1,%edi
    6d53:	e8 18 a5 ff ff       	call   1270 <exit@plt>
    6d58:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    6d5f:	00 
    6d60:	83 c1 01             	add    $0x1,%ecx
    6d63:	48 83 c6 04          	add    $0x4,%rsi
    6d67:	49 83 c4 01          	add    $0x1,%r12
    6d6b:	44 39 f9             	cmp    %r15d,%ecx
    6d6e:	0f 85 4c f8 ff ff    	jne    65c0 <susan_corners_quick+0x540>
    6d74:	66 0f 7e c0          	movd   %xmm0,%eax
    6d78:	44 89 c3             	mov    %r8d,%ebx
    6d7b:	45 01 d9             	add    %r11d,%r9d
    6d7e:	83 c0 01             	add    $0x1,%eax
    6d81:	66 0f 6e c0          	movd   %eax,%xmm0
    6d85:	3b 44 24 04          	cmp    0x4(%rsp),%eax
    6d89:	0f 85 e9 f7 ff ff    	jne    6578 <susan_corners_quick+0x4f8>
    6d8f:	48 63 44 24 10       	movslq 0x10(%rsp),%rax
    6d94:	48 8b 5c 24 40       	mov    0x40(%rsp),%rbx
    6d99:	48 8d 04 40          	lea    (%rax,%rax,2),%rax
    6d9d:	48 8d 04 c3          	lea    (%rbx,%rax,8),%rax
    6da1:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
    6da6:	c7 40 08 07 00 00 00 	movl   $0x7,0x8(%rax)
    6dad:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
    6db4:	5b                   	pop    %rbx
    6db5:	5d                   	pop    %rbp
    6db6:	41 5c                	pop    %r12
    6db8:	41 5d                	pop    %r13
    6dba:	41 5e                	pop    %r14
    6dbc:	41 5f                	pop    %r15
    6dbe:	c3                   	ret    
    6dbf:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
    6dc4:	eb e0                	jmp    6da6 <susan_corners_quick+0xd26>

Disassembly of section .fini:

0000000000006dc8 <_fini>:
    6dc8:	f3 0f 1e fa          	endbr64 
    6dcc:	48 83 ec 08          	sub    $0x8,%rsp
    6dd0:	48 83 c4 08          	add    $0x8,%rsp
    6dd4:	c3                   	ret    
