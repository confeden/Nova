// Matrix: five depth layers of digital rain, glyphs sampled from the baked atlas (16x8 cells of 24x32).
// Variety by construction: every column has its own speed (a 10x spread), its own length and gap, and 1-2 independent
// streams; every glyph cell has its own change rate and phase (a trail never flips in step); the head glyph churns fast.
// Hashes are integer (PCG) because the float h21 gave neighbouring columns correlated values, which read as
// batches of columns appearing together with the same rhythm.
uint mx_pcg(uint v){uint s=v*747796405u+2891336453u;uint w=((s>>((s>>28u)+4u))^s)*277803737u;return (w>>22u)^w;}
float mx_r(vec3 k){uint h=mx_pcg(uint(int(k.x))*73856093u^mx_pcg(uint(int(k.y))+19349663u)^mx_pcg(uint(int(k.z))*83492791u+7u));return float(h&16777215u)/16777216.;}
float glyph(float gi,vec2 f){vec2 uv=(f-vec2(.14,.1))/vec2(.72,.80);
 if(uv.x<0.||uv.y<0.||uv.x>1.||uv.y>1.)return 0.;
 vec2 cr=vec2(mod(gi,16.),floor(gi/16.));return textureLod(uAtlas,(cr+vec2(uv.x,1.-uv.y))/vec2(16.,8.),0.).r;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.1;float N=floor(tt);float fz=tt-N;
 alb=vec3(0.,.02,.012)+uBg*.3;emi=vec3(0);den=.8;h=0.;vec3 c=mix(uA,pal(.02),.15);
 for(int k=0;k<5;k++){float fk=float(k);float e=fk-fz;float A=fk+N;float rows=11.*exp2(e*.75);
  float al=smoothstep(4.,3.,e)*clamp(e+1.,0.,1.);float dim=mix(1.,.3,clamp(e/4.,0.,1.));
  vec2 q=vec2(p.x*rows*1.333,p.y*rows)+S+A*31.;float col=floor(q.x),row=floor(q.y);vec2 fr=fract(q);
  float gl=0.,br=0.,hd=0.;
  for(int s=0;s<2;s++){float fs=float(s);
   if(s==1&&mx_r(vec3(col,A,31.))<.62)continue;
   float rv=mx_r(vec3(col,A,1.+fs*10.));
   float sp=exp(mix(log(.35),log(3.6),rv*rv*(3.-2.*rv)))*3.2;          // rows per second, 10x spread
   float len=6.+26.*mx_r(vec3(col,A,2.+fs*10.));
   float gap=6.+90.*pow(mx_r(vec3(col,A,3.+fs*10.)),1.4);                 // long random silences
   float cyc=len+gap;
   float pos=mod(row+t*sp+mx_r(vec3(col,A,4.+fs*10.))*cyc*3.,cyc);        // distance behind the head, in rows (the head falls, the tail is above it)
   float b=pos<len?pow(1.-pos/len,1.8):0.;
   if(b>br){br=b;hd=pos<1.?1.:0.;}}
  if(br>0.){
   float rate=.12+mx_r(vec3(col,row,A+5.))*mx_r(vec3(col,row,A+9.))*4.5;   // each glyph its own change rate
   float ph=mx_r(vec3(col,row,A+13.));
   float gi=floor(mx_r(vec3(col,row,floor(t*rate+ph*50.)+A*101.))*120.);
   if(hd>.5)gi=floor(mx_r(vec3(col,row,floor(t*14.)+A*7.))*120.);
   gl=glyph(gi,fr);}
  emi+=(gl*(c*br*2.2+vec3(.75,1.,.85)*hd*4.)*dim+c*br*.03*dim)*al;
  h=max(h,gl*br*dim*al);den+=gl*br*5.*dim*al;}}
