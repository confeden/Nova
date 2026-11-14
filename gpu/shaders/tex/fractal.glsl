// Fractal 1: a Julia set dived into along the log-spiral of its repelling fixed point (two zoom levels cross-faded).
// Anti-aliased: 4 rotated-grid samples per pixel, and an orbit that neither escapes nor converges inside the budget is
// treated as lying ON the set boundary (a bright line), not as interior. Before, those pixels flipped between "inside"
// and "outside" from frame to frame, and the contrast edges shimmered.
vec2 cm(vec2 a,vec2 b){return vec2(a.x*b.x-a.y*b.y,a.x*b.y+a.y*b.x);}
void jl(vec2 p,vec2 c,vec2 beta,float ll,float la,float fz,float t,out vec3 eA,out vec3 aA,out float dA,out float hA){
 eA=vec3(0);aA=vec3(0);dA=0.;hA=0.;
 for(int lv=0;lv<2;lv++){float fl=fz-float(lv);float wl=lv==0?1.-fz:fz;
  float zs=.35*exp(-fl*ll);vec2 mm=exp(-fl*ll)*vec2(cos(fl*la),-sin(fl*la));
  vec2 z=beta+cm(p*.35,mm);vec2 dz=vec2(1.,0.);float n=0.,m=0.,tr=1e9;bool conv=false;
  for(int i=0;i<160;i++){dz=2.*vec2(z.x*dz.x-z.y*dz.y,z.x*dz.y+z.y*dz.x);z=vec2(z.x*z.x-z.y*z.y,2.*z.x*z.y)+c;m=dot(z,z);tr=min(tr,m);
   if(m>1e4)break;if(dot(dz,dz)<1e-6){conv=true;break;}n+=1.;}
  bool esc=m>1e4;bool ins=!esc&&(conv||dot(dz,dz)<1e4);
  float nu=esc?n+1.-log2(.5*log(m)):n;
  float de=esc?.25*sqrt(m)*log(m)/max(length(dz),1e-20)/zs:0.;
  // inside the set the distance to the boundary is unknown, but |dz| grows towards it: use it so the glow fades out on
  // BOTH sides of the boundary (a one-sided glow toggles from 0 to full when a boundary pixel flips between inside and out)
  float ldz=.5*log2(max(dot(dz,dz),1e-12));float lin=smoothstep(-2.,6.,ldz);lin=pow(lin,2.);
  float line=ins?lin:exp(-de*260.);float halo=ins?lin*.4:exp(-de*40.);
  vec3 col=pal(.2+.22*clamp(nu/70.,0.,1.)+t*.004);
  vec3 em=(ins?pal(.3+tr*.3)*.2*exp(-sqrt(tr)*2.):vec3(0.))+col*(line*3.+halo*.22);
  eA+=em*wl;aA+=(ins?vec3(.025,.035,.07):col*.12+.02)*wl;dA+=(ins?60.:2.+line*25.)*wl;hA+=(ins?.9:clamp(.25+halo*.6,0.,1.))*wl;}}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float a=t*.045+uSeed*.7;vec2 c=.5*vec2(cos(a),sin(a))-.25*vec2(cos(2.*a),sin(2.*a));c*=.965+.03*sin(t*.07+uSeed);
 vec2 sq=vec2(1.-4.*c.x,-4.*c.y);float am=.5*atan(sq.y,sq.x);vec2 beta=.5*(vec2(1.,0.)+sqrt(length(sq))*vec2(cos(am),sin(am)));
 vec2 lam=2.*beta;float ll=log(length(lam)),la=atan(lam.y,lam.x);
 float fz=fract(t*.045);float px=1./uRes.y;
 emi=vec3(0);alb=vec3(0);den=0.;h=0.;
 for(int s=0;s<4;s++){
  vec2 o=s==0?vec2(-.375,-.125):s==1?vec2(.125,-.375):s==2?vec2(.375,.125):vec2(-.125,.375);
  vec3 e,al;float d,hh;jl(p+o*px,c,beta,ll,la,fz,t,e,al,d,hh);
  emi+=e;alb+=al;den+=d;h+=hh;}
 emi*=.25;alb*=.25;den*=.25;h*=.25;}
