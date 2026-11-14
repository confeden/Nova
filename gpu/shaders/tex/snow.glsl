// Snow: six depth layers of falling flakes. Every flake is its own crystal: one of six habits (fern dendrite, hex plate with
// inner rings, sectored plate with broad branches, barbed star, twelve-sided star plate, capped column), with its own
// number, spacing and length of branches, branch angle, sub-branches, inner rings and tip shape, then a random
// foreshortening (it tumbles, so most are seen at a tilt) and a random line weight and tint. 6-fold symmetry by angle folding.
float segx(vec2 q,float L){q.x-=clamp(q.x,0.,L);return length(q);}
float segd(vec2 q,vec2 dir,float L){return length(q-dir*clamp(dot(q,dir),0.,L));}
float hexd(vec2 q){return q.x*.866+q.y*.5;}
float flake(vec2 q,float ty,vec4 r){float a=atan(q.y,q.x),rad=length(q);a=abs(mod(a+.5236,1.0472)-.5236);q=rad*vec2(cos(a),sin(a));
 float ba=.75+.45*r.x;vec2 dir=vec2(cos(ba),sin(ba));float d=1e9;
 if(ty<1.){ // fern dendrite
  float nb=3.+floor(r.y*3.);d=segx(q,1.);
  for(int i=0;i<5;i++){float fi=float(i);if(fi>=nb)break;
   float s=.1+.7*(fi+.2+.6*h21(vec2(fi,r.z*31.)))/nb;float l=(1.04-s)*(.38+.42*r.w)*(.75+.5*h21(vec2(fi,r.w*17.)));
   vec2 qb=q-vec2(s,0.);d=min(d,segd(qb,dir,l));
   vec2 qs=qb-dir*l*(.45+.25*h21(vec2(fi,r.x*9.)));vec2 d1=rot(.95)*dir,d2=rot(-.95)*dir;
   float ls=l*(.3+.25*r.z);d=min(d,min(segd(qs,d1,ls),segd(qs,d2,ls)));}
  d=min(d,segd(q-vec2(1.,0.),dir,.1));d=min(d,abs(rad-.09*(.6+r.w)));}
 else if(ty<2.){ // hex plate with inner rings
  float R1=.55+.35*r.y,R2=.18+.25*r.z;
  d=min(abs(hexd(q)-.866*R1),abs(hexd(q)-.866*R2));
  d=min(d,segx(q,R1*(.7+.5*r.w)));d=min(d,abs(rad-.07));
  if(r.x>.5)d=min(d,segd(q-vec2(R2,0.),dir,R1*.45));}
 else if(ty<3.){ // sectored plate with broad branches
  float R=.5+.25*r.y;d=segx(q,1.);d=min(d,abs(hexd(q)-.866*R));
  d=min(d,segd(q-vec2(R*.85,0.),dir,.3*(.6+r.z)));d=min(d,segd(q-vec2(R+.2,0.),dir,.14*(.6+r.w)));d=min(d,abs(rad-.12));}
 else if(ty<4.){ // barbed star
  d=segx(q,1.);int nb=2+int(r.y*3.);
  for(int i=0;i<4;i++){if(i>=nb)break;float s=.18+.2*float(i)*(.8+.4*r.z);d=min(d,segd(q-vec2(s,0.),dir,.1+.12*r.w*(1.-s*.5)));}
  d=min(d,length(q-vec2(1.,0.))-.02);}
 else if(ty<5.){ // twelve-sided star plate
  float R1=.55+.3*r.y,R2=.3+.3*r.z;
  d=min(abs(hexd(q)-.866*R1),abs(q.x-.866*R2));d=min(d,segx(q,R1));d=min(d,abs(rad-.1));}
 else{ // capped column seen end-on
  d=segx(q,.72);d=min(d,abs(length(q-vec2(.72,0.))-.16-.1*r.y));d=min(d,abs(rad-.18*(.5+r.z)));
  d=min(d,abs(hexd(q)-.866*(.3+.2*r.w)));}
 return d;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.08;float N=floor(tt);float fz=tt-N;float px=1.2/uRes.y;
 alb=vec3(.03,.05,.095)+.05*fbm(p*1.5+S+t*.01);emi=vec3(0);den=1.5;h=.1;
 for(int k=0;k<6;k++){float fk=float(k);float e=fk-fz;float A=fk+N;float f=2.6*exp2(e*.8);
  float al=smoothstep(5.,3.8,e)*clamp(e+1.,0.,1.);
  vec2 q=p*f+vec2(.35*sin(t*.3+A*1.7),t*.42)+A*13.1+S;vec2 id=floor(q),fr=fract(q)-.5;float rs=h21(id+A*5.);if(rs<.42)continue;
  float r2=h21(id+A+2.3);vec2 o=(h22(id+A)-.5)*.3;float R=.06+.25*r2*r2*r2+.04*r2;
  vec2 fo=fr-o;if(dot(fo,fo)>R*R*1.6)continue;
  float ty=floor(h21(id+A+8.1)*6.);float v=h21(id+A+21.);
  vec4 rr=vec4(h21(id+A+31.),h21(id+A+32.),h21(id+A+33.),h21(id+A+34.));
  // a falling flake spins slowly, rocks from side to side, and tumbles (its tilt, hence its foreshortening, keeps changing)
  float w1=.5+.9*h21(id+A+43.),ph1=h21(id+A+44.)*6.2832,ph2=h21(id+A+45.)*6.2832;
  float sq=.5+.5*(.5+.5*sin(t*(.35+.5*h21(id+A+46.))+ph2))*(.5+.5*h21(id+A+41.))+.18;
  float ang=rs*6.+t*.22*(rs-.5)*2.+.6*sin(t*w1+ph1);
  vec2 g=rot(ang)*fo/R;g.y/=min(sq,1.);float d=flake(g,ty,rr)*R/f;
  float rpx=R/f/px;float det=smoothstep(9.,20.,rpx);
  float w=max(.0016+.0014*rr.x,px*.9)*(.7+.6*v);float ln=1.-smoothstep(w,w+px,d);float halo=.18*exp(-d*220.);
  float soft=exp(-dot(fo,fo)/(R*R*.35))*smoothstep(0.,4.,rpx)*.7;
  vec3 c=mix(vec3(.82,.93,1.),pal(rs*2.+fk*.2),.15+.35*rr.y);
  emi+=c*mix(soft,ln*1.9+halo,det)*al*(.6+.4*rs);h=max(h,ln*det*al);den+=ln*det*6.*al;}}
