import './globals.css'

export const metadata = {
  title: 'TrustScan — Know before you open',
  description: 'Understand what an APK can access before you install it.',
}

export const viewport = {
  width: 'device-width',
  initialScale: 1,
}

export default function Layout({children}:{children:React.ReactNode}){
  return <html lang="en"><body>{children}</body></html>
}
