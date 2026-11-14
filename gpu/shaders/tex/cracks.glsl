// Cracks in glass: an endless dive into a pane that is being struck. Every impact is a spider web -- 7..12 straight radial
// cracks with small kinks and a couple of side branches each, linked by short chords at a few radii (the concentric
// polygon rings of real shattered glass) -- and it GROWS: each crack front runs out from the impact point at its own
// speed, tapering to a hairline at the tip, the chords draw in after the rays have passed their radius. There is no
// tint that follows a growth radius (it read as an expanding circle). Cracks are bright thin edges with a dark core on a deep tinted
// glass, no network of organic veins. Five zoom layers, the layer's age comes from its zoom phase, so nothing restarts.
float rh(vec2 g,float A,float j,float k){return h21(g*1.93+vec2(j*3.17+k*11.3,A*5.1+k*2.7+j));}
float cr_seg(vec2 p,vec2 a,vec2 b,out float k){vec2 pa=p-a,ba=b-a;k=clamp(dot(pa,ba)/max(dot(ba,ba),1e-9),0.,1.);return length(pa-ba*k);}
vec2 cr_pt(vec2 O,vec2 dir,float s,float s1,float L,float kA,float kB){
 vec2 perp=vec2(-dir.y,dir.x);float lat=s<s1?kA*s/max(s1,1e-4):mix(kA,kB,(s-s1)/max(L-s1,1e-4));return O+dir*s+perp*lat;}
// one impact; adds to cv (crack coverage), glw (soft glow); fac is unused
// cv.x = light cracks (brightness weighted), cv.y = dark cracks; every impact leans to light or dark, every crack differs
void cr_imp(vec2 c,vec2 g,float A,float tau,float aa,inout vec2 cv,inout float glw,inout float fac){
 if(h21(g+A*2.9+3.)<.86)return;
 float ta=tau-(1.5+2.*h21(g+A*2.3+5.));if(ta<=0.)return;     // an impact starts only once its layer is fully in view, and grows from nothing
 vec2 O=g+.18+.64*h22(g*1.31+A*7.1+11.);vec2 d=c-O;float rr=length(d);
 float Lb=1.05+.9*h21(g+A+7.7);if(rr>Lb*1.3)return;
 float fn=5.+floor(h21(g+A+9.3)*8.);float pdark=h21(g+A*1.7+.3);float rp=h21(g+A+.9);float a0=6.2832*h21(g+A+13.);
 float ang=atan(d.y,d.x)-a0;ang-=6.2832*floor(ang/6.2832);float u=ang/6.2832*fn;float i0=floor(u);
 vec2 Qr[6];float Gr[2];float Ls[2];
 for(int s=0;s<2;s++){
  float i=i0+float(s);float im=mod(i,fn);
  float th=a0+(i+(rh(g,A,im,0.)-.5)*.55)*6.2832/fn;vec2 dir=vec2(cos(th),sin(th));
  float L=Lb*(.5+.65*rh(g,A,im,1.));float v=1.6+4.4*pow(rh(g,A,im,2.),1.5);float grown=ta*v;float l=min(grown,L);
  float kA=(rh(g,A,im,3.)-.5)*.16,kB=(rh(g,A,im,4.)-.5)*.24;float s1=L*(.28+.3*rh(g,A,im,5.));
  Gr[s]=grown;Ls[s]=L;
  for(int k=0;k<3;k++){float Rk=Lb*(.2+.24*float(k))*(.9+.2*h21(g+A+float(k)*3.3));
   Qr[s*3+k]=cr_pt(O,dir,min(Rk,L),s1,L,kA,kB);if(Rk>L)Gr[s]=min(Gr[s],-1.);}   // a ray shorter than the ring cannot carry it
  if(l<=0.)continue;
  float w0=(.011+.008*rh(g,A,im,6.))*(.55+.6*L);float wmax=aa*(.45+.55*rh(g,A,im,14.));
  float dk=step(rh(g,A,im,12.),pdark*1.15);float bj=.4+.75*rh(g,A,im,13.);
  // main crack: two straight pieces with a kink; a partial second piece while it is still growing
  vec2 V1=cr_pt(O,dir,s1,s1,L,kA,kB);float k1,k2;float d1,d2=9.;float sa1,sa2=0.;
  if(l<=s1){vec2 E=cr_pt(O,dir,l,s1,L,kA,kB);d1=cr_seg(c,O,E,k1);sa1=k1*l;}
  else{d1=cr_seg(c,O,V1,k1);sa1=k1*s1;vec2 E=cr_pt(O,dir,l,s1,L,kA,kB);d2=cr_seg(c,V1,E,k2);sa2=s1+k2*(l-s1);}
  float dm,sa;if(d1<d2){dm=d1;sa=sa1;}else{dm=d2;sa=sa2;}
  float w=clamp(w0*pow(clamp(1.-sa/max(l,1e-3),0.,1.),.75),.28*aa,wmax);
  float cc=1.-smoothstep(w-aa*.45,w+aa*.7,dm);if(dk>.5)cv.y=max(cv.y,cc);else cv.x=max(cv.x,cc*bj);glw=max(glw,exp(-dm/(w*2.5+aa*1.5))*.7);
  // side branches: grow once the front has passed their root
  for(int b=0;b<2;b++){float fb=float(b);
   if(rh(g,A,im,7.+fb*5.)<.38+.2*fb)continue;
   float sb=L*(.3+.35*rh(g,A,im,8.+fb*5.));if(grown<=sb)continue;
   vec2 Bp=cr_pt(O,dir,sb,s1,L,kA,kB);float sd=(b==0?1.:-1.)*(rh(g,A,im,9.+fb*5.)<.5?-1.:1.);
   vec2 db=rot(sd*(.28+.3*rh(g,A,im,10.+fb*5.)))*dir;float Lbr=L*(.16+.24*rh(g,A,im,11.+fb*5.));float lb=min((grown-sb)*.9,Lbr);
   float kb;float dd=cr_seg(c,Bp,Bp+db*lb,kb);float wb=clamp(w0*.6*pow(clamp(1.-kb,0.,1.),.7),.28*aa,.7*wmax);
   float cb=1.-smoothstep(wb-aa*.45,wb+aa*.7,dd);if(dk>.5)cv.y=max(cv.y,cb);else cv.x=max(cv.x,cb*bj);glw=max(glw,exp(-dd/(wb*2.5+aa*1.5))*.45);}
 }
 // chords between neighbouring rays at three radii
 float w0c=.007*(.55+.6*Lb);
 for(int k=0;k<3;k++){
  float Rk=Lb*(.2+.24*float(k))*(.9+.2*h21(g+A+float(k)*3.3));
  float pk=(k==0?.9:(k==1?.72:.55))*rp*1.5;if(h21(g+A+vec2(i0*1.7+float(k)*5.3,2.5))>pk)continue;
  float ready=min(Gr[0],Gr[1])-Rk;if(ready<=0.)continue;
  float fr=clamp(ready*.9,0.,1.);vec2 qa=Qr[k],qb=Qr[3+k];float kc;
  float dd=cr_seg(c,qa,qa+(qb-qa)*fr,kc);float wc=clamp(w0c*(1.-.7*kc*kc),.28*aa,.6*aa);
  float cch=1.-smoothstep(wc-aa*.45,wc+aa*.7,dd);if(h21(g+A+vec2(float(k),7.7))<pdark*1.15)cv.y=max(cv.y,cch);else cv.x=max(cv.x,cch*(.45+.55*h21(g+A+vec2(float(k),3.3))));glw=max(glw,exp(-dd/(wc*2.5+aa*1.5))*.4);} }
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.06;float N=floor(tt);float fz=tt-N;float px=1./uRes.y;
 vec2 pc=p-vec2(.03,.02);
 float cr=0.,cd=0.,glo=0.,fct=0.,gn=0.,W=0.;
 for(int k=0;k<5;k++){
  float fk=float(k);float e=fk-fz;float A=fk+N;float f=1.1*exp2(e);
  float al=clamp(e+1.,0.,1.)*smoothstep(3.6,2.8,e);float tau=4.3-e;
  vec2 c=rot(A*.7)*pc*f+S+A*5.3;vec2 ci=floor(c);
  float aa=1.2*px*f;
  vec2 cv=vec2(0.);float glw=0.,fac=0.;
  for(int j=0;j<9;j++)cr_imp(c,ci+vec2(float(j%3-1),float(j/3-1)),A,tau,aa,cv,glw,fac);
  cr=1.-(1.-cr)*(1.-cv.x*al);cd=1.-(1.-cd)*(1.-cv.y*al);glo=max(glo,glw*al);
  float x=clamp((e+1.)/5.,0.,1.);float wh=.5-.5*cos(6.2832*x);gn+=wh*(vn(c*40.+A)*.5+vn(c*130.+A*3.)*.5);W+=wh;}
 gn/=max(W,1e-3);
 float sheen=exp(-pow((dot(p,vec2(.8,.6))-(fract(t*.012)*3.-1.5))*2.6,2.))*.08;
 vec3 glass=vec3(.085,.1,.13)+uB*.06+uA*.03;
 alb=glass*(1.+(gn-.5)*.35)*(1.-.8*cr)*(1.-.93*cd);
 vec3 ce=mix(vec3(.86,.95,1.),uA*1.5,.2);
 emi=ce*cr*.8+uA*glo*glo*.1+uB*sheen;
 h=.72-(cr+cd)*.3;den=mix(5.,1.4,max(cr,cd));}
