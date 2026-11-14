void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float tt=t*.07;float N=floor(tt);float fz=tt-N;
 float sw=fbm(p*2.2+S+vec2(t*.03,-t*.025));float depth=smoothstep(.6,-.5,p.y);
 alb=mix(vec3(.02,.04,.06),vec3(.01,.02,.04),depth)+.025*sw;emi=uA*.06*pow(sw,3.);den=2.;h=.2+.08*sw;
 vec3 cA=mix(uA,vec3(.8,.93,1.),.35);
 for(int k=0;k<4;k++){float fk=float(k);float e=fk-fz;float A=fk+N;float f=2.2*exp2(e*.85);
  float al=smoothstep(3.,2.2,e)*clamp(e+1.,0.,1.);
  float cx=floor(p.x*f*16.+A*5.);float rc=h21(vec2(cx,A+2.));
  if(rc>.55){float dx=abs(fract(p.x*f*16.+A*5.)-.5-(h21(vec2(cx,A+7.))-.5)*.5);float ph=fract(p.y*f*.7+t*(.9+1.4*rc)+rc*9.);
   emi+=vec3(.7,.85,1.)*exp(-dx*dx/.0012)*pow(max(1.-ph*5.,0.),2.)*smoothstep(0.,.02,ph)*.22*al;}
  vec2 q=p*f+S+A*11.3;vec2 ci=floor(q);
  for(int y=-1;y<=1;y++)for(int x=-1;x<=1;x++){vec2 c=ci+vec2(float(x),float(y));float r0=h21(c+A*3.1);if(r0<.7)continue;
   float per=2.5+3.*h21(c+4.4+A);float u=t/per+r0*17.;float n=floor(u),life=fract(u);
   vec2 rr=h22(c+n*.7+A);vec2 ip=c+.5+(rr-.5)*.6;vec2 d=q-ip;float dist=length(d);if(dist>2.2)continue;
   float sz=.55+.45*h21(c+n*1.3+A);float fade=smoothstep(1.,.5,life);float R=life*(1.+.7*sz);float ring=0.;
   for(int j=0;j<2;j++){float rj=R-float(j)*.18;if(rj>0.)ring+=exp(-pow((dist-rj)/(.035+.01*float(j)),2.))*exp(-rj*2.2)*(1.-float(j)*.35);}
   emi+=cA*ring*fade*.55*al;h+=ring*fade*.08*al;
   emi+=vec3(1.)*exp(-dist*dist*300.)*exp(-life*18.)*1.4*al;
   float cw=.08+.1*sqrt(life);emi+=vec3(.85,.95,1.)*exp(-pow((dist-cw)/.025,2.))*exp(-life*6.)*.7*sz*al;
   for(int j=0;j<5;j++){float fj=float(j);float hj=h21(vec2(fj*3.7+n,c.x+c.y*1.7));float ang=6.2832*(fj+hj*.8)/5.;vec2 dir=vec2(cos(ang),sin(ang));
    float sp=.5+.8*h21(vec2(fj,c.y+n*2.3))*sz;float tl=life/.6;if(tl>=1.)continue;
    float rad=.08+sp*(1.-(1.-tl)*(1.-tl));vec2 pd=ip+dir*rad;float len=.07*(1.-tl)+.01;vec2 ba=-dir*len;vec2 pa=q-pd;
    float hs=clamp(dot(pa,ba)/dot(ba,ba),0.,1.);float sd2=length(pa-ba*hs);float wdt=.01*(1.-.5*tl)+.003;
    emi+=vec3(.9,.97,1.)*exp(-sd2*sd2/(wdt*wdt))*(1.-tl)*1.2*al;}
   den+=exp(-dist*dist*60.)*3.*al;}}}