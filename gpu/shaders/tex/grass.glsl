// Meadow: a walk through grass, in perspective. The ground is a cheap low-grass carpet (streaky noise, no stems); on it
// stand plants of four kinds and many heights -- grass blades, tall stalks with seed heads, broad leaves, and flower
// stems -- and the flowers come in six kinds (daisy, poppy, bluebell, dandelion, cosmos, violet). Everything bends with the wind.
float petal(vec2 d,float R,float n,float rr,float sharp){float a=atan(d.y,d.x)+rr;float r=length(d);float s=pow(.5+.5*cos(a*n),sharp);float e=R*(.30+.70*s);return smoothstep(e,e*.8,r);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 const float HZ=.17;const float EY=.62;const int NR=16;
 float tt=t*.11;float N=floor(tt);float fz=tt-N;float px=1.2/uRes.y;
 float sky=smoothstep(HZ,.75,p.y);
 vec3 hor=mix(vec3(.04,.07,.12),uA*.35,.5);
 alb=mix(hor,vec3(.015,.025,.075),sky);emi=pal(.6)*.07*(1.-sky)*(1.-sky);den=1.5;h=.05;
 if(p.y<HZ){float z=EY/(HZ-p.y+1e-3);float Lw=log(z)*4.05+tt*4.05;float gx=p.x*z;
  float g=fbm(vec2(gx*1.3,Lw*.6)+S);float fg=exp(-z*.05);
  // low grass carpet: short streaks along the depth axis at three scales, finer ones fading with distance (no aliasing)
  float f1=exp(-z*.07),f2=exp(-z*.16),f3=exp(-z*.3);
  float s1=mix(.5,vn(vec2(gx*26.+S.x,Lw*2.4)),f1);float s2=mix(.5,vn(vec2(gx*85.+7.,Lw*7.)),f2);float s3=mix(.5,h21(floor(vec2(gx*150.,Lw*16.))),f3);
  float tone=clamp(.12+.42*g+.3*s1+.2*s2+.14*s3,0.,1.);
  vec3 low=mix(vec3(.012,.04,.016),vec3(.075,.17,.05),tone);
  low=mix(low,vec3(.2,.32,.07),smoothstep(.82,1.,s3)*f3*.8);          // sunlit tips
  low*=(.55+.5*exp(-z*.08));
  alb=mix(hor,low,fg);
  emi=pal(.3+g*.2)*.03*fg;h=.05+.06*s2*f2;}
 for(int k=NR-1;k>=0;k--){float fk=float(k);float e=fk-fz;float A=fk+N;
  float z=.9*pow(1.28,e);float by=HZ-EY/z;
  float a=smoothstep(float(NR)-1.,float(NR)-3.,e)*clamp(e+.9,0.,1.);
  float fog=exp(-z*.055);
  float fr=h21(vec2(A,uSeed+9.));
  if(fr>.62){vec2 fp=vec2((h21(vec2(A,2.))-.5)*1.5+.12*sin(t*.4+A),by+(.05+.30*h21(vec2(A,3.)))/z+.015/z*sin(t*1.3+A*3.));
   vec2 dd=p-fp;float rr=.0035+.007/z;
   emi+=mix(vec3(1.,.92,.45),uA,.35)*exp(-dot(dd,dd)/(rr*rr))*3.5*(.5+.5*sin(t*2.1+A*4.))*a;}
  float yyc=p.y-by;if(yyc>.52/z||yyc<-.004)continue;
  float dxw=.05;float ro=h21(vec2(A,5.))*dxw;float xw=p.x*z-ro;float c0=floor(xw/dxw);
  for(int j=-2;j<=2;j++){float c=c0+float(j);float r1=h21(vec2(c,A)),r2=h21(vec2(c+.5,A+3.));
   float r3=h21(vec2(c+.25,A+11.));
   float ty=r3<.45?0.:(r3<.62?1.:(r3<.8?2.:3.));                       // blade, stalk with seed head, broad leaf, flower stem
   float hf=ty<.5?(.8+.5*r2):(ty<1.5?(1.7+.8*r1):(ty<2.5?(.55+.4*r2):(1.2+1.2*r1)));
   float xb=(c+.5+(r1-.5)*.9)*dxw+ro;float x0=xb/z;float Hw=.11*hf*(.6+.8*r2);float Hs=Hw/z;float yy=yyc/Hs;
   float gust=vn(vec2(xb*.8-t*.5,A*.3+t*.12));float wind=(gust-.5)*1.7+.3*sin(t*1.1+xb*3.+A);
   float bk=(wind*.55+(r1-.5)*.35)*Hs;float cx=x0+bk*yy*yy;
   if(yy>0.&&yy<1.){
    float w=ty<.5?.0085*(1.-yy*.85)*(.7+.6*r2):(ty<1.5?.0066*(1.-.25*yy):(ty<2.5?.021*pow(sin(3.1416*clamp(yy,0.,1.)),.6)*(.8+.5*r1)+.002:.0052*(1.-.25*yy)));
    w=max(w/z,.8*px);float m=smoothstep(w,w*.3,abs(p.x-cx))*a;
    float lum=.45+.55*exp(-z*.05);
    vec3 base=ty<1.5?vec3(.30,.62,.17):(ty<2.5?vec3(.16,.5,.2):vec3(.2,.55,.15));
    vec3 col=mix(vec3(.02,.09,.03),mix(base,pal(.12+r1*.12),.22),yy)*lum;
    if(ty>1.5&&ty<2.5)col=mix(col,col*1.5+.05,smoothstep(.03,0.,abs(p.x-cx))*.5);          // midrib of a leaf
    alb=mix(alb,mix(hor,col,fog),m);emi=mix(emi,pal(r1*.2)*pow(yy,3.)*.45*lum*fog,m);h=mix(h,.3+.6*yy,m);den=mix(den,6.+14./(1.+z*.3),m);}
   if(ty>.5&&ty<1.5){                                                          // seed head of a tall stalk
    vec2 sc=vec2(x0+bk*.81,by+.9*Hs);vec2 dq=(p-sc)/(vec2(.011,.05)/z);float sm=smoothstep(1.,.65,length(dq))*a;
    vec3 sc3=mix(vec3(.7,.58,.22),vec3(.86,.78,.4),h21(vec2(c,A+1.)));
    alb=mix(alb,sc3*.6,sm);emi=mix(emi,sc3*.9*fog,sm);h=mix(h,.85,sm);den=mix(den,4.,sm);}
   if(ty>2.5||(ty<.5&&r2>.9)){vec2 tp=vec2(x0+bk,by+Hs);float R=max(.032*(.8+.5*r1)/z,2.*px);vec2 d=p-tp;float ld=length(d);
    if(ld<R*1.2){float fk2=h21(vec2(c+.7,A+2.));float rot0=r1*6.;
     float n5=5.;float sharp=1.;vec3 pc0=vec3(1.);vec3 ctr=vec3(1.,.8,.2);float cr0=.2;
     if(fk2<.17){n5=11.;sharp=2.4;pc0=vec3(.97,.97,1.);ctr=vec3(1.,.78,.15);cr0=.3;}               // daisy
     else if(fk2<.34){n5=4.;sharp=.55;pc0=vec3(.95,.12,.08);ctr=vec3(.1,.04,.07);cr0=.22;}         // poppy
     else if(fk2<.5){n5=5.;sharp=.9;pc0=mix(vec3(.4,.55,1.),uA*2.,.2);ctr=vec3(.9,.92,1.);cr0=.18;} // bluebell
     else if(fk2<.66){n5=22.;sharp=1.6;pc0=vec3(1.,.82,.1);ctr=vec3(1.,.55,.05);cr0=.35;}           // dandelion
     else if(fk2<.83){n5=8.;sharp=1.2;pc0=vec3(1.,.5,.75);ctr=vec3(1.,.85,.2);cr0=.22;}            // cosmos
     else{n5=6.;sharp=1.4;pc0=vec3(.66,.42,1.);ctr=vec3(.95,.8,1.);cr0=.2;}                          // violet
     pc0=mix(pc0,pc0.gbr,.12*r2);
     float pm=petal(d,R,n5,rot0,sharp);float cm=smoothstep(cr0*R,cr0*R*.6,ld);
     vec3 pc=mix(pc0,pc0*.7,smoothstep(.25,.9,ld/R));
     vec3 fcol=mix(pc,ctr,cm);float fm=max(pm,cm)*a;
     alb=mix(alb,fcol*.8,fm);emi=mix(emi,fcol*mix(1.6,3.,cm)*fog,fm);h=mix(h,.8,fm);den=mix(den,4.,fm);}}}}}
