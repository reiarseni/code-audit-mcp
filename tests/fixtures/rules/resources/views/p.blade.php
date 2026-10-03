<div>{!! $post->body !!}</div>{{-- BAD:blade-unescaped-output --}}
<div>{{ $safe }}</div>
