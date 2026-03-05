function ReviewCard({ review }) {
  return (
    <article className="review-card premium-review-card">
      <p className="review-quote">"{review.quote}"</p>
      <div className="review-foot">
        <strong>{review.name}</strong>
        <small>{review.meta}</small>
      </div>
    </article>
  );
}

export default ReviewCard;
