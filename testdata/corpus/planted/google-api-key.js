// Shipped to the browser, which is how it got scraped the first time.
const MAPS_KEY = "AIzaSyD7wKq2ZmT4bXn9Ld6VcP1YsA3EjH5uGf0";

export function loader() {
  return `https://maps.googleapis.com/maps/api/js?key=${MAPS_KEY}`;
}
