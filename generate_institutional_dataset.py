"""
Generate training dataset for academic and government domains
Includes Indian and international institutions
"""
import pandas as pd
import random

# Indian Academic Institutions (.ac.in)
INDIAN_ACADEMIC = [
    'iitb.ac.in', 'iitd.ac.in', 'iitm.ac.in', 'iitk.ac.in', 'iitkgp.ac.in',
    'iisc.ac.in', 'bits-pilani.ac.in', 'du.ac.in', 'jnu.ac.in', 'bhu.ac.in',
    'nit.ac.in', 'nitk.ac.in', 'nitt.ac.in', 'nitw.ac.in', 'vnit.ac.in',
    'ksit.ac.in', 'rvce.edu.in', 'bmsce.ac.in', 'msrit.edu', 'bmsit.ac.in',
    'pesu.ac.in', 'cmrit.ac.in', 'dsce.edu.in', 'sjce.ac.in', 'nie.ac.in',
    'amrita.edu', 'vit.ac.in', 'manipal.edu', 'christ.edu.in', 'sjbit.edu.in',
    'anna.ac.in', 'cutn.ac.in', 'nitt.edu', 'jadavpur.edu.in', 'calcutta.ac.in',
    'thapar.edu', 'dtu.ac.in', 'nsit.ac.in', 'igdtuw.ac.in', 'ipu.ac.in',
    'kiit.ac.in', 'gitam.edu', 'srm.ac.in', 'srmist.edu.in', 'sastra.edu',
    'pondiuni.edu.in', 'makautonline.ac.in', 'mu.ac.in', 'unipune.ac.in'
]

# Indian Government Domains (.gov.in, .nic.in)
INDIAN_GOVERNMENT = [
    'india.gov.in', 'uidai.gov.in', 'incometax.gov.in', 'gst.gov.in',
    'irctc.co.in', 'epfindia.gov.in', 'esic.nic.in', 'india.gov.in',
    'mygov.in', 'digitalindia.gov.in', 'makeinindia.gov.in', 'pmindia.gov.in',
    'mea.gov.in', 'mhrd.gov.in', 'mof.gov.in', 'pib.gov.in', 'eci.gov.in',
    'rbi.org.in', 'sebi.gov.in', 'cbdt.gov.in', 'cbic.gov.in', 'cag.gov.in',
    'upsc.gov.in', 'ssc.nic.in', 'nta.ac.in', 'aicte-india.org', 'ugc.ac.in',
    'railways.gov.in', 'air.gov.in', 'doordarshan.gov.in', 'ddnews.gov.in',
    'mha.gov.in', 'mod.gov.in', 'dae.gov.in', 'drdo.gov.in', 'isro.gov.in',
    'morth.nic.in', 'nhai.gov.in', 'mohua.gov.in', 'passportindia.gov.in'
]

# International Academic Domains
INTERNATIONAL_ACADEMIC = [
    'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'princeton.edu',
    'yale.edu', 'columbia.edu', 'cornell.edu', 'upenn.edu', 'caltech.edu',
    'ox.ac.uk', 'cam.ac.uk', 'imperial.ac.uk', 'ucl.ac.uk', 'eth.ch',
    'ntu.edu.sg', 'nus.edu.sg', 'utoronto.ca', 'ubc.ca', 'mcgill.ca',
    'tsinghua.edu.cn', 'pku.edu.cn', 'u-tokyo.ac.jp', 'kyoto-u.ac.jp',
    'unimelb.edu.au', 'sydney.edu.au', 'unsw.edu.au', 'anu.edu.au'
]

# International Government Domains
INTERNATIONAL_GOVERNMENT = [
    'usa.gov', 'whitehouse.gov', 'state.gov', 'irs.gov', 'nasa.gov',
    'census.gov', 'nih.gov', 'cdc.gov', 'fda.gov', 'sec.gov',
    'gov.uk', 'parliament.uk', 'nhs.uk', 'homeoffice.gov.uk',
    'canada.ca', 'gc.ca', 'australia.gov.au', 'singapore.gov.sg'
]

def generate_benign_urls(domains, num_per_domain=5):
    """Generate benign URL variations for training"""
    urls = []
    
    paths = [
        '/', '/index.html', '/about', '/contact', '/home', '/login',
        '/admissions', '/courses', '/faculty', '/research', '/events',
        '/news', '/downloads', '/apply', '/services', '/portal'
    ]
    
    for domain in domains:
        # HTTPS versions
        for _ in range(num_per_domain):
            path = random.choice(paths)
            urls.append({
                'url': f'https://www.{domain}{path}',
                'label': 'benign',
                'source': 'institutional'
            })
            
            # Without www
            urls.append({
                'url': f'https://{domain}{path}',
                'label': 'benign',
                'source': 'institutional'
            })
    
    return urls

def generate_training_dataset():
    """Generate complete training dataset"""
    print("=" * 80)
    print("GENERATING ACADEMIC & GOVERNMENT TRAINING DATASET")
    print("=" * 80)
    
    all_urls = []
    
    # Indian Academic
    print(f"\n✓ Generating URLs for {len(INDIAN_ACADEMIC)} Indian academic domains...")
    all_urls.extend(generate_benign_urls(INDIAN_ACADEMIC, num_per_domain=3))
    
    # Indian Government
    print(f"✓ Generating URLs for {len(INDIAN_GOVERNMENT)} Indian government domains...")
    all_urls.extend(generate_benign_urls(INDIAN_GOVERNMENT, num_per_domain=3))
    
    # International Academic
    print(f"✓ Generating URLs for {len(INTERNATIONAL_ACADEMIC)} international academic domains...")
    all_urls.extend(generate_benign_urls(INTERNATIONAL_ACADEMIC, num_per_domain=3))
    
    # International Government
    print(f"✓ Generating URLs for {len(INTERNATIONAL_GOVERNMENT)} international government domains...")
    all_urls.extend(generate_benign_urls(INTERNATIONAL_GOVERNMENT, num_per_domain=3))
    
    # Create DataFrame
    df = pd.DataFrame(all_urls)
    
    # Save to CSV
    output_file = 'institutional_training_data.csv'
    df.to_csv(output_file, index=False)
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {len(df)} training URLs")
    print(f"✅ Saved to: {output_file}")
    print("=" * 80)
    
    # Statistics
    print("\nDataset Statistics:")
    print(f"  Indian Academic URLs: {len([u for u in all_urls if '.ac.in' in u['url'] or '.edu.in' in u['url']])}")
    print(f"  Indian Government URLs: {len([u for u in all_urls if '.gov.in' in u['url'] or '.nic.in' in u['url']])}")
    print(f"  International Academic URLs: {len([u for u in all_urls if '.edu' in u['url'] and '.in' not in u['url']])}")
    print(f"  International Government URLs: {len([u for u in all_urls if '.gov' in u['url'] and '.in' not in u['url']])}")
    
    # Show sample
    print("\nSample URLs:")
    for url_data in random.sample(all_urls, min(10, len(all_urls))):
        print(f"  {url_data['url']}")
    
    return df

if __name__ == "__main__":
    df = generate_training_dataset()
    print("\n✅ Dataset generation complete!")
    print("📊 Use this file to retrain your model with institutional domain support")
