// Constellations: the nova.gratis / Android network background as a shader. Drifting nodes joined by thin
// lines that fade with length, a soft glow on nodes, slow pulses. One jittered-grid cell holds at most one
// node (it wanders inside its cell on sin drift), each pixel looks at the 3x3 cells around it and draws the
// 8-neighbour links between them. Three depth layers dive endlessly (recipe in kb light-lab.md).
// Every node sits at a "home" inside its cell, then hops to a new home (eased glide, at its own rhythm) and rests, so the
// graph keeps re-forming: links stretch as nodes part, vanish beyond their reach, and new ones draw in as nodes meet other
// nodes. A small wander keeps resting nodes alive. Links carry travelling pulses.
vec2 cn_home(vec2 key,float n){return .13+.74*h22(key*1.71+n*13.7+4.3);}
vec4 cn_pt(vec2 key,float t){
 vec2 r=h22(key);float pr=h21(key+3.17);
 float per=40.+60.*h21(key+1.3);float u=(t+h21(key+5.5)*per*7.)/per;float n=floor(u);float fr=fract(u);
 float s=smoothstep(0.,1.,fr);                                      // one soft glide that never rests long: peak speed ~3x lower than before, so links stretch and fade gradually
 vec2 o=mix(cn_home(key,n),cn_home(key,n+1.),s);
 o+=.03*sin(t*(.2+.3*r)+r.yx*6.2832);
 return vec4(o,fract(pr*13.7+r.x*5.3)*6.2832,pr<.1?-1.:.85+1.55*fract(pr*31.7));}
// Whether a link may exist at all, decided per PAIR of nodes and changing only over minutes: each pair has its own period
// (100-240 s) and every moment is a slow cross-fade between its previous and its next state, so a link melts in and out
// over ~a minute -- far too slowly to be seen as a rebuild, even when the animation is sped up many times.
float cn_gate(vec2 ka,vec2 kb,float t){
 float pid=h21(ka+kb+17.7+abs(ka-kb)*3.1);float per=100.+140.*h21(vec2(pid*53.1,1.7));
 float u=t/per+fract(pid*91.7);float n=floor(u);float s=smoothstep(0.,1.,u-n);
 float b0=step(h21(vec2(pid*97.3,n*7.1+3.3)),.78),b1=step(h21(vec2(pid*97.3,n*7.1+10.4)),.78);
 return mix(b0,b1,s);}
float cn_seg(vec2 q,vec2 a,vec2 b,out float k){vec2 pa=q-a,ba=b-a;k=clamp(dot(pa,ba)/dot(ba,ba),0.,1.);return length(pa-ba*k);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float px=1./uRes.y;float sc=max(uRes.y/700.,.3);
 float tt=t*.045;float N=floor(tt);float fz=tt-N;
 alb=vec3(.016,.02,.038);emi=vec3(0);den=.35;h=0.;
 for(int k=0;k<3;k++){
  float e=float(k)-fz;float A=mod(float(k)+N,64.);
  float al=smoothstep(2.,1.,e)*clamp(e+1.,0.,1.);
  if(al<.004)continue;
  float lum=al*mix(1.,.5,clamp(e*.5,0.,1.));
  float f=3.6*exp2(e*.8);
  vec2 q=rot(.5+A*1.7)*p*f+t*vec2(.016,.01)+A*vec2(7.3,3.7)+S;
  vec2 id=floor(q),fr=q-id;
  float pxc=px*f;
  vec4 P[9];
  for(int j=0;j<3;j++)for(int i=0;i<3;i++){
   vec2 of=vec2(float(i-1),float(j-1));
   vec4 v=cn_pt(id+of,t);v.xy+=of;P[j*3+i]=v;}
  for(int a=0;a<9;a++){
   if(P[a].w<0.)continue;
   int ax=a-(a/3)*3,ay=a/3;
   for(int s=0;s<4;s++){
    int bx=ax+(s==3?-1:(s==2?0:1));int by=ay+(s==0?0:1);
    if(bx<0||bx>2||by>2)continue;
    int b=by*3+bx;if(P[b].w<0.)continue;
    vec2 ab=P[b].xy-P[a].xy;float len=length(ab);
    float ph=P[a].z+P[b].z;float R=.95+.4*fract(ph*3.7);
    float lk=smoothstep(R,R*.08,len);if(lk<=.003)continue;
    lk*=cn_gate(id+vec2(float(ax-1),float(ay-1)),id+vec2(float(bx-1),float(by-1)),t);if(lk<=.003)continue;                    // very wide, single-eased fade by length: a link takes several seconds to draw in or die away
    vec2 md=fr-(P[a].xy+P[b].xy)*.5;float rr=len*.5+pxc*14.;if(dot(md,md)>rr*rr)continue;
    float kk;float d=cn_seg(fr,P[a].xy,P[b].xy,kk);if(d>pxc*14.)continue;
    float pu=.5+.5*sin(t*(.2+.15*fract(ph*5.1))+ph);
    float w=.62*pxc;float ln=1.-smoothstep(w,w+pxc*1.1,d);
    float halo=exp(-d/(pxc*3.5));
    vec3 c=mix(uA,pal(.13*ph+A*.07),.4);
    float pz=fract(t*(.12+.1*fract(ph*2.3))+ph);float pulse=exp(-pow((kk-pz)*len/.07,2.))*step(.5,fract(ph*7.7));
    emi+=c*(ln*(1.25+2.*pulse)+halo*(.22+.5*pulse))*lk*(.62+.38*pu)*lum;
    h=max(h,ln*lk*.4);den+=ln*lk*.5*lum;}}
  for(int a=0;a<9;a++){
   if(P[a].w<0.)continue;
   vec2 dv=fr-P[a].xy;float d2=dot(dv,dv);
   float rb=max(P[a].w*1.28*sc*1.5,1.1)*pxc;if(d2>rb*rb*60.)continue;
   float pu=.5+.5*sin(t*1.4+P[a].z);
   float rp=max(P[a].w*(1.+.28*pu)*sc*1.5,1.1);float rc=rp*pxc;
   float d=sqrt(d2);
   float core=1.-smoothstep(rc,rc+pxc*1.2,d);
   float gl=exp(-d*d/(rc*rc*14.+1e-6));
   vec3 nc=mix(vec3(.9,.94,1.),uB,.3);
   float na=(.57+.33*pu)*lum;
   emi+=nc*(core*2.4+gl*.55)*na;
   h=max(h,core*.7*lum);den+=core*2.*lum;}
 }}
