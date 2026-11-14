// Aurora, seen while walking north beneath it. The curtains hang in the sky over a flat world: a curtain at depth D with its
// lower edge at altitude a0 appears at screen height y = horizon + a0/D, so as we walk on (D shrinks) every curtain rises
// out of the horizon, swells, sweeps overhead and leaves the top of the frame -- the aurora moves back behind us.
// Rays are vertical in the world (vertical on screen, spreading outward as the curtain nears). A curtain is born far away
// as a faint stretch of its length, grows brighter and longer while it comes, and thins out as it passes overhead; each
// cycle has its own phase, colours, folds and extent, so there is never a repeat. Stars sit behind, a spruce line in front.
#define AU_P 16.
vec3 au_band(vec2 p,float t,float b){
 float yh=-.32;float dy=p.y-yh;if(dy<.004)return vec3(0.);float hz=smoothstep(.004,.16,dy);
 float u=(b*.7+3.)*AU_P/4.-t*.33;                       // distance of this band's curtain, decreasing as we walk
 float cyc=floor(u/AU_P);float D0=mod(u,AU_P)+.8;       // far -> near
 vec2 key=vec2(b*7.1+cyc*3.7,uSeed+cyc*1.3);
 float ph=h21(key)*6.2832,ph2=h21(key+3.)*6.2832;
 float a0=.55+.5*h21(key+5.);float Hc=1.4+1.6*h21(key+7.);
 float x=p.x;
 float D=D0*(1.+.22*sin(x*1.9+ph+t*.04)+.11*sin(x*4.3+ph2-t*.07)+.05*sin(x*9.1+ph*1.7+t*.12));   // the curtain's line bends and folds
 float X=x*D;float a=dy*D;float hh=a-a0;
 float born=smoothstep(AU_P+.8,AU_P*.3,D);born*=born*(3.-2.*born);float gone=smoothstep(.9,2.2,D);
 float seg=smoothstep(.25,.75,vn(vec2(X*.11+ph,cyc*5.3+b)));
 seg*=.55+.45*smoothstep(.3,.8,vn(vec2(X*.31+ph2,t*.04+b)));
 float env=born*gone*seg*(.45+1.1*h21(key+9.));
 if(env<.004)return vec3(0.);
 float low=smoothstep(-.3,.45,hh);
 float k=1.6+1.8*h21(key+11.);float prof=low*exp(-max(hh,0.)*k/(Hc*.5));
 float r1=vn(vec2(X*5.1+b*7.,t*.35+b*3.));float r2=vn(vec2(X*14.+b,t*.8+b));float r3=vn(vec2(X*1.7+b,t*.12));
 float ray=smoothstep(.2,.9,r1*.5+r2*.3+r3*.2);
 float rv=vn(vec2(X*7.,hh*2.5-t*.6+b*5.));
 float I=env*prof*(.14+1.55*ray)*(.65+.6*rv);
 float rim=exp(-abs(hh-.1)*3.5)*env*(.3+.7*r3)*smoothstep(-.4,.0,hh);
 float hf=clamp(hh/Hc*1.8,0.,1.);
 vec3 c0=mix(uA,pal(b*.29+.05+.2*h21(key+13.)),.5);
 vec3 c=mix(mix(c0*1.3,uB*1.1,smoothstep(0.,.35,hf)),uC*1.2,smoothstep(.3,1.,hf));
 return (c*I*1.5+mix(c0,vec3(1.),.4)*rim*.1)*hz;}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 vec2 sp=rot(t*.002)*p;float px=1./uRes.y;
 vec2 c1=floor((sp+S)*uRes.y*.55);float s1=h21(c1);
 float st=step(.9965,s1)*(.35+.65*h21(c1+3.))*(.8+.2*sin(t*1.3+s1*60.));
 vec2 c2=floor((sp+S)*70.);vec2 f2=fract((sp+S)*70.)-.5-(h22(c2)-.5)*.6;
 float big=step(.93,h21(c2+9.))*exp(-dot(f2,f2)*(900.)/(1.+3.*h21(c2+1.)));
 vec3 stars=vec3(.8,.9,1.)*st*1.1+mix(vec3(.8,.9,1.),vec3(1.,.9,.75),h21(c2+4.))*big*1.6;
 vec3 au=vec3(0.);
 for(int b=0;b<5;b++)au+=au_band(p,t,float(b));
 au*=.55;
 { float l0=dot(au,vec3(.33));au=max(vec3(l0)+(au-vec3(l0))*1.55,0.); }     // richer colour
 float lum=dot(au,vec3(.33));
 float horiz=exp(-max(p.y+.32,0.)*5.);                                         // the sky glows near the horizon
 vec3 sky=mix(vec3(.004,.007,.016),vec3(.012,.02,.04),smoothstep(-.5,.5,p.y))+uBg*.4;
 alb=sky;emi=au+stars*(1.-clamp(lum*1.4,0.,.85))+uA*horiz*.035;den=2.5+lum*3.;h=0.;
 // spruce line: a hilly ridge with jagged crowns, in front of everything
 float x=p.x;float cell=floor(x*46.);float hs=.018+.05*h21(vec2(cell,3.7));float tri=1.-abs(fract(x*46.)-.5)*2.;
 float ys=-.37+.04*fbm(vec2(x*2.6+S.x,3.))+hs*pow(tri,1.5)*smoothstep(.3,.6,fbm(vec2(x*3.+S.y,9.)))+.012*sin(x*13.+uSeed);
 float gr=smoothstep(px*1.5,-px*1.5,p.y-ys);
 alb=mix(alb,vec3(.003,.005,.008),gr);emi=mix(emi,au*.04,gr);den=mix(den,60.,gr);h=gr*.4;}
