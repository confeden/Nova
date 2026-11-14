// Fractal 2: an endless dive into the Julia set of z^2+c. The view is not zoomed in a plane: it is looked at through
// the Poincare function P of the repelling fixed point beta (P(lam*w)=f(P(w)), lam=2*beta), P(w)=f^n(beta+w/lam^n)
// with the 2nd-order Koenigs correction. The picture at w/lam is the picture at w pushed one step along the orbit, so
// a zoom by lam (with its rotation: the log spiral) gives EXACTLY the same image: one phase fz=fract(t*rate) is enough,
// no cross-fade, no restart. Colours depend on the escape time through cos(2*pi*nu): period 1 in nu, so the shift of nu
// by an integer per cycle (see below) is invisible. The parameter walks the main cardioid on the arc |lam|=1.3 (fixed), arg lam within +-0.38; one cycle is lam^3 (zoom 2.2, up to 65 deg of spiral turn), so nu shifts by 3.
vec2 cm(vec2 a,vec2 b){return vec2(a.x*b.x-a.y*b.y,a.x*b.y+a.y*b.x);}
void tex(vec2 p,float t,out vec3 alb,out vec3 emi,out float den,out float h){
 float th=.38*sin(t*.043+uSeed*.9);vec2 lam=1.3*vec2(cos(th),sin(th));
 vec2 mu=vec2(2.,0.)-lam;vec2 beta=.5*lam;vec2 alpha=.5*mu;float mr=length(mu);
 vec2 c=beta-cm(beta,beta);
 float ll=log(length(lam)),la=atan(lam.y,lam.x);
 float n=clamp(ceil(log(150.)/ll),5.,24.);
 float fz=fract(t*.32);
 float sc=exp(-fz*3.*ll);
 vec2 w=cm(rot(t*.07)*p*4.6,sc*vec2(cos(3.*fz*la),-sin(3.*fz*la)));
 float zs=4.6*sc;
 vec2 lamn=exp(-n*ll)*vec2(cos(n*la),-sin(n*la));
 vec2 a2=cm(lam,lam-vec2(1.,0.));a2=vec2(a2.x,-a2.y)/dot(a2,a2);
 vec2 u=cm(w,lamn);
 vec2 z=beta+u+cm(a2,cm(u,u));vec2 dz=cm(vec2(1.,0.)+2.*cm(a2,u),lamn);
 float k=0.,m=0.;bool esc=false,fat=false;
 for(int i=0;i<120;i++){
  dz=2.*cm(z,dz);z=cm(z,z)+c;m=dot(z,z);
  if(m>1e4){esc=true;break;}
  vec2 dd=z-alpha;if(dot(dd,dd)<4e-6){fat=true;break;}
  if(dot(dz,dz)>1e24)break;
  k+=1.;}
 float tw=6.2831853;float lmu=-log(mr);
 vec3 e=vec3(0),a=vec3(0);float d=2.,hh=.3;
 if(esc){
  float nu=k+1.-log2(.5*log(m))-n;
  float de=.25*sqrt(m)*log(m)/max(length(dz),1e-20)/zs;
  float line=exp(-de*260.),halo=exp(-de*40.);
  float cb=.5+.5*cos(tw*nu);
  vec3 col=pal(.12+.34*cb+t*.004);
  float c6=cb*cb*cb;c6*=c6;e=col*(line*3.+halo*.3+.07*cb*exp(-de*3.)+.5*c6*exp(-de*2.5));a=col*.12+.02;d=2.+line*25.;hh=clamp(.25+halo*.6,0.,1.);
 }else if(fat){
  vec2 dd=z-alpha;
  float ni=k-n+log(sqrt(dot(dd,dd))/.002)/lmu;
  float cb=.5+.5*cos(tw*ni);
  e=pal(.62+.3*cb+t*.004)*(.012+.045*cb)*exp(-ni*.03);a=vec3(.025,.035,.07);d=60.;hh=.9;
 }else{
  vec3 col=pal(.5+t*.004);e=col*3.2;a=col*.12+.02;d=30.;hh=.8;}
 emi=e;alb=a;den=d;h=hh;}
