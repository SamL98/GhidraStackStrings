push rdi
push rsi
push rax

call ${strlen_plus_5}
${str}
pop rsi

@if (off == 0)
@if (reg.lower() != 'rax')
push reg
@endif
pop rdi
@else
lea rdi, [${reg} + ${off}]
@endif

call ${strcpy}

@if (off != 0 or reg.lower() != 'rax')
pop rax
@endif
pop rsi
pop rdi
