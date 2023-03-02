
benchmark:     file format elf64-x86-64


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

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp *0x2f75(%rip)        # 3fd0 <puts@GLIBC_2.2.5>
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
    1078:	48 8d 3d 1c 02 00 00 	lea    0x21c(%rip),%rdi        # 129b <main>
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

0000000000001149 <foo>:
#include <stdio.h>
#include <stdlib.h>

typedef void(*FUNC)();

void foo() {
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   %rbp
    114e:	48 89 e5             	mov    %rsp,%rbp
	puts("foo");
    1151:	48 8d 05 ac 0e 00 00 	lea    0xeac(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1158:	48 89 c7             	mov    %rax,%rdi
    115b:	e8 f0 fe ff ff       	call   1050 <puts@plt>
}
    1160:	90                   	nop
    1161:	5d                   	pop    %rbp
    1162:	c3                   	ret    

0000000000001163 <indirectCall>:

void indirectCall(FUNC pointer) {
    1163:	f3 0f 1e fa          	endbr64 
    1167:	55                   	push   %rbp
    1168:	48 89 e5             	mov    %rsp,%rbp
    116b:	48 83 ec 10          	sub    $0x10,%rsp
    116f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
	if (NULL == pointer) {
    1173:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    1178:	74 0d                	je     1187 <indirectCall+0x24>
		return;
	}
	return pointer();
    117a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    117e:	b8 00 00 00 00       	mov    $0x0,%eax
    1183:	ff d2                	call   *%rdx
    1185:	eb 01                	jmp    1188 <indirectCall+0x25>
		return;
    1187:	90                   	nop
}
    1188:	c9                   	leave  
    1189:	c3                   	ret    

000000000000118a <directCall>:

int directCall(int var) {
    118a:	f3 0f 1e fa          	endbr64 
    118e:	55                   	push   %rbp
    118f:	48 89 e5             	mov    %rsp,%rbp
    1192:	89 7d fc             	mov    %edi,-0x4(%rbp)
	return var >> 1;
    1195:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1198:	d1 f8                	sar    %eax
}
    119a:	5d                   	pop    %rbp
    119b:	c3                   	ret    

000000000000119c <indirectJump>:

int indirectJump(int var) {
    119c:	f3 0f 1e fa          	endbr64 
    11a0:	55                   	push   %rbp
    11a1:	48 89 e5             	mov    %rsp,%rbp
    11a4:	89 7d fc             	mov    %edi,-0x4(%rbp)
	switch (var) {
    11a7:	83 7d fc 06          	cmpl   $0x6,-0x4(%rbp)
    11ab:	77 49                	ja     11f6 <indirectJump+0x5a>
    11ad:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11b0:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    11b7:	00 
    11b8:	48 8d 05 49 0e 00 00 	lea    0xe49(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    11bf:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    11c2:	48 98                	cltq   
    11c4:	48 8d 15 3d 0e 00 00 	lea    0xe3d(%rip),%rdx        # 2008 <_IO_stdin_used+0x8>
    11cb:	48 01 d0             	add    %rdx,%rax
    11ce:	3e ff e0             	notrack jmp *%rax
		case 0: break;
		case 1: --var; break;
    11d1:	83 6d fc 01          	subl   $0x1,-0x4(%rbp)
    11d5:	eb 1f                	jmp    11f6 <indirectJump+0x5a>
		case 2: var -= 2; break;
    11d7:	83 6d fc 02          	subl   $0x2,-0x4(%rbp)
    11db:	eb 19                	jmp    11f6 <indirectJump+0x5a>
		case 3: var -= 3; break;
    11dd:	83 6d fc 03          	subl   $0x3,-0x4(%rbp)
    11e1:	eb 13                	jmp    11f6 <indirectJump+0x5a>
		case 4: var -= 4; break;
    11e3:	83 6d fc 04          	subl   $0x4,-0x4(%rbp)
    11e7:	eb 0d                	jmp    11f6 <indirectJump+0x5a>
		case 5: var -= 5; break;
    11e9:	83 6d fc 05          	subl   $0x5,-0x4(%rbp)
    11ed:	eb 07                	jmp    11f6 <indirectJump+0x5a>
		case 6: var -= 6; break;
    11ef:	83 6d fc 06          	subl   $0x6,-0x4(%rbp)
    11f3:	eb 01                	jmp    11f6 <indirectJump+0x5a>
		case 0: break;
    11f5:	90                   	nop
	}
	return var;
    11f6:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    11f9:	5d                   	pop    %rbp
    11fa:	c3                   	ret    

00000000000011fb <indirectJumpMirror>:

int indirectJumpMirror(int var) {
    11fb:	f3 0f 1e fa          	endbr64 
    11ff:	55                   	push   %rbp
    1200:	48 89 e5             	mov    %rsp,%rbp
    1203:	89 7d fc             	mov    %edi,-0x4(%rbp)
	switch (var) {
    1206:	83 7d fc 06          	cmpl   $0x6,-0x4(%rbp)
    120a:	77 49                	ja     1255 <indirectJumpMirror+0x5a>
    120c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    120f:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    1216:	00 
    1217:	48 8d 05 06 0e 00 00 	lea    0xe06(%rip),%rax        # 2024 <_IO_stdin_used+0x24>
    121e:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    1221:	48 98                	cltq   
    1223:	48 8d 15 fa 0d 00 00 	lea    0xdfa(%rip),%rdx        # 2024 <_IO_stdin_used+0x24>
    122a:	48 01 d0             	add    %rdx,%rax
    122d:	3e ff e0             	notrack jmp *%rax
		case 0: break;
		case 1: --var; break;
    1230:	83 6d fc 01          	subl   $0x1,-0x4(%rbp)
    1234:	eb 1f                	jmp    1255 <indirectJumpMirror+0x5a>
		case 2: var -= 2; break;
    1236:	83 6d fc 02          	subl   $0x2,-0x4(%rbp)
    123a:	eb 19                	jmp    1255 <indirectJumpMirror+0x5a>
		case 3: var -= 3; break;
    123c:	83 6d fc 03          	subl   $0x3,-0x4(%rbp)
    1240:	eb 13                	jmp    1255 <indirectJumpMirror+0x5a>
		case 4: var -= 4; break;
    1242:	83 6d fc 04          	subl   $0x4,-0x4(%rbp)
    1246:	eb 0d                	jmp    1255 <indirectJumpMirror+0x5a>
		case 5: var -= 5; break;
    1248:	83 6d fc 05          	subl   $0x5,-0x4(%rbp)
    124c:	eb 07                	jmp    1255 <indirectJumpMirror+0x5a>
		case 6: var -= 6; break;
    124e:	83 6d fc 06          	subl   $0x6,-0x4(%rbp)
    1252:	eb 01                	jmp    1255 <indirectJumpMirror+0x5a>
		case 0: break;
    1254:	90                   	nop
	}
	return var;
    1255:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    1258:	5d                   	pop    %rbp
    1259:	c3                   	ret    

000000000000125a <fib>:

int fib(int n) {
    125a:	f3 0f 1e fa          	endbr64 
    125e:	55                   	push   %rbp
    125f:	48 89 e5             	mov    %rsp,%rbp
    1262:	53                   	push   %rbx
    1263:	48 83 ec 18          	sub    $0x18,%rsp
    1267:	89 7d ec             	mov    %edi,-0x14(%rbp)
	if (n <= 2) {
    126a:	83 7d ec 02          	cmpl   $0x2,-0x14(%rbp)
    126e:	7f 07                	jg     1277 <fib+0x1d>
		return 1;
    1270:	b8 01 00 00 00       	mov    $0x1,%eax
    1275:	eb 1e                	jmp    1295 <fib+0x3b>
	}
	return fib(n-1) + fib(n-2);
    1277:	8b 45 ec             	mov    -0x14(%rbp),%eax
    127a:	83 e8 01             	sub    $0x1,%eax
    127d:	89 c7                	mov    %eax,%edi
    127f:	e8 d6 ff ff ff       	call   125a <fib>
    1284:	89 c3                	mov    %eax,%ebx
    1286:	8b 45 ec             	mov    -0x14(%rbp),%eax
    1289:	83 e8 02             	sub    $0x2,%eax
    128c:	89 c7                	mov    %eax,%edi
    128e:	e8 c7 ff ff ff       	call   125a <fib>
    1293:	01 d8                	add    %ebx,%eax
}
    1295:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
    1299:	c9                   	leave  
    129a:	c3                   	ret    

000000000000129b <main>:

int main() {
    129b:	f3 0f 1e fa          	endbr64 
    129f:	55                   	push   %rbp
    12a0:	48 89 e5             	mov    %rsp,%rbp
    12a3:	48 83 ec 10          	sub    $0x10,%rsp
	int b = 10;
    12a7:	c7 45 fc 0a 00 00 00 	movl   $0xa,-0x4(%rbp)

	puts("indirectCall");
    12ae:	48 8d 05 8b 0d 00 00 	lea    0xd8b(%rip),%rax        # 2040 <_IO_stdin_used+0x40>
    12b5:	48 89 c7             	mov    %rax,%rdi
    12b8:	e8 93 fd ff ff       	call   1050 <puts@plt>
	indirectCall(foo);
    12bd:	48 8d 05 85 fe ff ff 	lea    -0x17b(%rip),%rax        # 1149 <foo>
    12c4:	48 89 c7             	mov    %rax,%rdi
    12c7:	e8 97 fe ff ff       	call   1163 <indirectCall>

	fib(b);
    12cc:	8b 45 fc             	mov    -0x4(%rbp),%eax
    12cf:	89 c7                	mov    %eax,%edi
    12d1:	e8 84 ff ff ff       	call   125a <fib>

	puts("directCall");
    12d6:	48 8d 05 70 0d 00 00 	lea    0xd70(%rip),%rax        # 204d <_IO_stdin_used+0x4d>
    12dd:	48 89 c7             	mov    %rax,%rdi
    12e0:	e8 6b fd ff ff       	call   1050 <puts@plt>
	b = directCall(b);
    12e5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    12e8:	89 c7                	mov    %eax,%edi
    12ea:	e8 9b fe ff ff       	call   118a <directCall>
    12ef:	89 45 fc             	mov    %eax,-0x4(%rbp)

	puts("indirectJump");
    12f2:	48 8d 05 5f 0d 00 00 	lea    0xd5f(%rip),%rax        # 2058 <_IO_stdin_used+0x58>
    12f9:	48 89 c7             	mov    %rax,%rdi
    12fc:	e8 4f fd ff ff       	call   1050 <puts@plt>
	b = indirectJump(b);
    1301:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1304:	89 c7                	mov    %eax,%edi
    1306:	e8 91 fe ff ff       	call   119c <indirectJump>
    130b:	89 45 fc             	mov    %eax,-0x4(%rbp)

	if (b) {
    130e:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    1312:	74 11                	je     1325 <main+0x8a>
		puts("b != 0");
    1314:	48 8d 05 4a 0d 00 00 	lea    0xd4a(%rip),%rax        # 2065 <_IO_stdin_used+0x65>
    131b:	48 89 c7             	mov    %rax,%rdi
    131e:	e8 2d fd ff ff       	call   1050 <puts@plt>
    1323:	eb 0f                	jmp    1334 <main+0x99>
	} else {
		puts("b == 0");
    1325:	48 8d 05 40 0d 00 00 	lea    0xd40(%rip),%rax        # 206c <_IO_stdin_used+0x6c>
    132c:	48 89 c7             	mov    %rax,%rdi
    132f:	e8 1c fd ff ff       	call   1050 <puts@plt>
	}

	puts("indirectJumpMirror");
    1334:	48 8d 05 38 0d 00 00 	lea    0xd38(%rip),%rax        # 2073 <_IO_stdin_used+0x73>
    133b:	48 89 c7             	mov    %rax,%rdi
    133e:	e8 0d fd ff ff       	call   1050 <puts@plt>
	b = indirectJump(b);
    1343:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1346:	89 c7                	mov    %eax,%edi
    1348:	e8 4f fe ff ff       	call   119c <indirectJump>
    134d:	89 45 fc             	mov    %eax,-0x4(%rbp)

	fib(b);
    1350:	8b 45 fc             	mov    -0x4(%rbp),%eax
    1353:	89 c7                	mov    %eax,%edi
    1355:	e8 00 ff ff ff       	call   125a <fib>
	
	puts("indirectCall");
    135a:	48 8d 05 df 0c 00 00 	lea    0xcdf(%rip),%rax        # 2040 <_IO_stdin_used+0x40>
    1361:	48 89 c7             	mov    %rax,%rdi
    1364:	e8 e7 fc ff ff       	call   1050 <puts@plt>
	indirectCall(foo);
    1369:	48 8d 05 d9 fd ff ff 	lea    -0x227(%rip),%rax        # 1149 <foo>
    1370:	48 89 c7             	mov    %rax,%rdi
    1373:	e8 eb fd ff ff       	call   1163 <indirectCall>


	return 0;
    1378:	b8 00 00 00 00       	mov    $0x0,%eax
}
    137d:	c9                   	leave  
    137e:	c3                   	ret    

Disassembly of section .fini:

0000000000001380 <_fini>:
    1380:	f3 0f 1e fa          	endbr64 
    1384:	48 83 ec 08          	sub    $0x8,%rsp
    1388:	48 83 c4 08          	add    $0x8,%rsp
    138c:	c3                   	ret    
