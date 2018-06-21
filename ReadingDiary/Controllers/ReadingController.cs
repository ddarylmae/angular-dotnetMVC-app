﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Web.Http.Description;
using ReadingDiary.Models;

namespace ReadingDiary.Controllers
{
    [Authorize]
    [EnableCors(origins: "http://localhost:4200", headers: "*", methods: "*")]
    public class ReadingController : ApiController
    {
        private ReadingDiaryEntities db = new ReadingDiaryEntities();

        //GET: api/Reading
        public IQueryable<Reading> GetReadings()
        {
            Int32.TryParse(User.Identity.Name, out int userId);
            return db.Readings.Where(r => r.UserId == userId).OrderByDescending(x => x.DateRead);
        }        

        // GET: api/Reading/5
        [ResponseType(typeof(Reading))]
        public IHttpActionResult GetReading(int id)
        {
            Reading reading = db.Readings.Find(id);
            if (reading == null)
            {
                return NotFound();
            }
            return Ok(reading);
        }

        [HttpGet, Route("api/reading/count")]
        public IHttpActionResult GetReadingsCount()
        {
            int count = 0;
            count = GetReadings().Count();
            return Ok(count);
        }

        [HttpGet, Route("api/reading/{id}/category")]
        public IQueryable<Reading> GetReadingByCategory(int id)
        {
            return GetReadings().Where(r => r.Category==id);
        }

        [HttpGet, Route("api/reading/latest")]
        public IHttpActionResult GetLatestReading()
        {            
            Reading reading = GetReadings().FirstOrDefault();
            if (reading == null)
            {
                return NotFound();
            }
            return Ok(reading);
        }

        [HttpPut, Route("api/reading/{id}/fave")]
        public IHttpActionResult UpdateFavoriteStatus(int id)
        {
            Reading reading = db.Readings.Find(id);
            if (reading == null)
            {
                return NotFound();
            }
            else
            {
                reading.Favorite = (reading.Favorite==1) ? 0 : 1;
                PutReading(id, reading);
            }
            return Ok(reading);
        }

        // PUT: api/Reading/5
        [ResponseType(typeof(void))]
        public IHttpActionResult PutReading(int id, Reading reading)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != reading.Id)
            {
                return BadRequest();
            }

            db.Entry(reading).State = EntityState.Modified;

            try
            {
                db.SaveChanges();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ReadingExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/Reading
        [ResponseType(typeof(Reading))]
        public IHttpActionResult PostReading(Reading reading)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            Int32.TryParse(User.Identity.Name, out int userId);
            reading.UserId = userId;
            db.Readings.Add(reading);
            db.SaveChanges();

            return CreatedAtRoute("DefaultApi", new { id = reading.Id }, reading);
        }

        // DELETE: api/Reading/5
        [ResponseType(typeof(Reading))]
        public IHttpActionResult DeleteReading(int id)
        {
            Reading reading = db.Readings.Find(id);
            if (reading == null)
            {
                return NotFound();
            }

            db.Readings.Remove(reading);
            db.SaveChanges();

            return Ok(reading);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool ReadingExists(int id)
        {
            return db.Readings.Count(e => e.Id == id) > 0;
        }


    }
}